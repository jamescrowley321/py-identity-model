# py-identity-model Makefile
# Run `make help` to see all available targets.

CONFORMANCE_SERVER ?= https://www.certification.openid.net/
ACTION ?= create

# ── Build ────────────────────────────────────────────────────────────

.PHONY: build-dist
build-dist: ## Build wheel and sdist
	uv sync
	uv build

.PHONY: upload-dist
upload-dist: ## Publish package to PyPI
	uv publish

# ── Lint ─────────────────────────────────────────────────────────────

.PHONY: lint
lint: ## Run all pre-commit hooks (ruff, pyrefly, coverage)
	uv run pre-commit run -a

# ── Tests ────────────────────────────────────────────────────────────

.PHONY: test
test: ## Run all tests (unit + integration)
	uv run pytest src/tests -v -n auto --cov=src/py_identity_model --cov-report=term-missing --cov-report=html --cov-fail-under=80 --ignore=src/tests/benchmarks -p no:benchmark

.PHONY: test-unit
test-unit: ## Run unit tests only
	uv run pytest src/tests -m unit -v -n auto --cov=src/py_identity_model --cov-report=term-missing --cov-report=html --cov-fail-under=80 --ignore=src/tests/benchmarks -p no:benchmark

.PHONY: test-integration-local
test-integration-local: ## Run integration tests against local provider
	uv run pytest src/tests -m integration --env-file=.env.local -v -n auto -p no:benchmark

.PHONY: test-integration-ory
test-integration-ory: ## Run integration tests against Ory
	uv run pytest src/tests -m integration -v -n auto -p no:benchmark

.PHONY: test-integration-descope
test-integration-descope: ## Run integration tests against Descope
	@echo "Running integration tests against Descope..."
	uv run pytest src/tests -m integration $(if $(wildcard .env.descope),--env-file=.env.descope) -v -n auto -p no:benchmark

.PHONY: test-integration-node-oidc
test-integration-node-oidc: ## Run integration tests against node-oidc-provider
	@echo "Starting node-oidc-provider fixture..."
	docker compose -f test-fixtures/node-oidc-provider/docker-compose.yml up -d --build --wait
	@echo "Running integration tests against node-oidc-provider..."
	uv run pytest src/tests -m integration --env-file=.env.node-oidc -v || \
		(docker compose -f test-fixtures/node-oidc-provider/docker-compose.yml down && exit 1)
	docker compose -f test-fixtures/node-oidc-provider/docker-compose.yml down

.PHONY: test-benchmark
test-benchmark: ## Run benchmarks
	uv run pytest src/tests/benchmarks -v --benchmark-only --benchmark-sort=name

.PHONY: test-examples
test-examples: ## Run example integration tests (Docker)
	@echo "Running example integration tests..."
	cd examples && ./run-tests.sh

.PHONY: test-all
test-all: test test-examples ## Run all tests including examples

# ── Docs ─────────────────────────────────────────────────────────────

.PHONY: docs-serve
docs-serve: ## Serve mkdocs documentation locally
	uv run --group docs mkdocs serve

.PHONY: docs-build
docs-build: ## Build mkdocs documentation
	uv run --group docs mkdocs build --strict

# ── Utilities ────────────────────────────────────────────────────────

.PHONY: provider-matrix
provider-matrix: ## Show provider capability matrix from discovery documents
	uv run python src/tests/integration/provider_matrix.py

.PHONY: generate-token
generate-token: ## Generate a sample JWT token
	uv run python examples/generate_token.py

.PHONY: ci-setup
ci-setup: ## CI environment setup
	python -m pip install --upgrade pip
	pip install pipx
	pipx install uv
	uv venv
	uv sync --all-packages

# ── Conformance ──────────────────────────────────────────────────────

.PHONY: conformance-build
conformance-build: ## Build conformance suite containers
	docker compose -f conformance/docker-compose.yml build

.PHONY: conformance-up
conformance-up: ## Start conformance suite and RP harness
	docker compose -f conformance/docker-compose.yml up -d --build --wait

.PHONY: conformance-down
conformance-down: ## Tear down conformance suite
	docker compose -f conformance/docker-compose.yml down -v

.PHONY: conformance-test
conformance-test: $(if $(HOSTED),,conformance-up) ## Run conformance tests (HOSTED=1 for hosted suite)
ifdef HOSTED
	python conformance/run_tests.py --plan basic-rp --suite-url $(CONFORMANCE_SERVER) --output conformance/results/hosted/basic-rp-latest.json --verbose
	python conformance/run_tests.py --plan config-rp --suite-url $(CONFORMANCE_SERVER) --output conformance/results/hosted/config-rp-latest.json --verbose
	@echo "Hosted conformance tests complete. Results in conformance/results/hosted/"
else
	python conformance/run_tests.py --plan basic-rp --output conformance/results/basic-rp-latest.json --verbose
	python conformance/run_tests.py --plan config-rp --output conformance/results/config-rp-latest.json --verbose
	@echo "Conformance tests complete. Results in conformance/results/"
endif

.PHONY: conformance-test-harness
conformance-test-harness: ## Run conformance harness unit tests (parser + callback)
	uv run --with fastapi --with httpx --with python-multipart pytest conformance/tests/ -v

.PHONY: conformance-token
conformance-token: ## Manage OIDF API token (ACTION=create|show|env)
ifeq ($(ACTION),show)
	uv run conformance/scripts/rotate_conformance_token.py --dry-run --show-token
else ifeq ($(ACTION),env)
	@echo "export CONFORMANCE_TOKEN=$$(hcp vault-secrets secrets open CONFORMANCE_TOKEN --app py-identity-model --format json | jq -r '.static_version.value')"
	@echo "# Run the above command, or: eval \$$(make conformance-token ACTION=env)"
else
	@echo "Launching browser for certification.openid.net login..."
	@echo "First run: sign in via Google/GitLab in the browser window."
	@echo "Subsequent runs: session is cached in ~/.cache/py-identity-model/playwright-profile/"
	uv run conformance/scripts/rotate_conformance_token.py
endif

# ── Help ─────────────────────────────────────────────────────────────

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-30s\033[0m %s\n", $$1, $$2}'
