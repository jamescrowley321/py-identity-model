.PHONY: build-dist
build-dist:
	uv sync
	uv build

.PHONY: upload-dist
upload-dist:
	uv publish

.PHONY: lint
lint:
	uv run pre-commit run -a

.PHONY: test
test:
	uv run pytest src/tests -v -n auto --cov=src/py_identity_model --cov-report=term-missing --cov-report=html --cov-fail-under=80 --ignore=src/tests/benchmarks -p no:benchmark

.PHONY: test-unit
test-unit:
	uv run pytest src/tests -m unit -v -n auto --cov=src/py_identity_model --cov-report=term-missing --cov-report=html --cov-fail-under=80 --ignore=src/tests/benchmarks -p no:benchmark

.PHONY: test-integration-local
test-integration-local:
	uv run pytest src/tests -m integration --env-file=.env.local -v -n auto -p no:benchmark

.PHONY: test-integration-ory
test-integration-ory:
	uv run pytest src/tests -m integration -v -n auto -p no:benchmark

.PHONY: test-integration-descope
test-integration-descope:
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

.PHONY: provider-matrix
provider-matrix: ## Show provider capability matrix from discovery documents
	uv run python src/tests/integration/provider_matrix.py

.PHONY: generate-token
generate-token:
	uv run python examples/generate_token.py

.PHONY: test-benchmark
test-benchmark:
	uv run pytest src/tests/benchmarks -v --benchmark-only --benchmark-sort=name

.PHONY: test-examples
test-examples:
	@echo "Running example integration tests..."
	cd examples && ./run-tests.sh

.PHONY: test-all
test-all: test test-examples

.PHONY: docs-serve
docs-serve:
	uv run --group docs mkdocs serve

.PHONY: docs-build
docs-build:
	uv run --group docs mkdocs build --strict

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
conformance-test: conformance-up ## Run all conformance profiles against local suite
	python conformance/run_tests.py --plan basic-rp --output conformance/results/basic-rp-latest.json --verbose
	python conformance/run_tests.py --plan config-rp --output conformance/results/config-rp-latest.json --verbose
	@echo "Conformance tests complete. Results in conformance/results/"

.PHONY: conformance-test-harness
conformance-test-harness: ## Run conformance harness unit tests (parser + callback)
	uv run --with fastapi --with httpx --with python-multipart pytest conformance/tests/ -v

.PHONY: conformance-token
conformance-token: ## Create OIDF API token via Playwright and push to HCP Vault Secrets
	@echo "Launching browser for certification.openid.net login..."
	@echo "First run: sign in via Google/GitLab in the browser window."
	@echo "Subsequent runs: session is cached in ~/.cache/py-identity-model/playwright-profile/"
	uv run conformance/scripts/rotate_conformance_token.py

.PHONY: conformance-token-show
conformance-token-show: ## Create token and print to stderr (dry run, no Vault push)
	uv run conformance/scripts/rotate_conformance_token.py --dry-run --show-token

.PHONY: conformance-token-env
conformance-token-env: ## Pull CONFORMANCE_TOKEN from HCP Vault and print export command
	@echo "export CONFORMANCE_TOKEN=$$(hcp vault-secrets secrets open CONFORMANCE_TOKEN --app py-identity-model --format json | jq -r '.static_version.value')"
	@echo "# Run the above command, or: eval \$$(make conformance-token-env)"

.PHONY: conformance-cert-dryrun
conformance-cert-dryrun: ## Run conformance tests against certification.openid.net (requires CONFORMANCE_TOKEN)
	@if [ -z "$$CONFORMANCE_TOKEN" ]; then \
		echo "Error: CONFORMANCE_TOKEN is not set."; \
		echo ""; \
		echo "To get a token:"; \
		echo "  make conformance-token        # creates token + pushes to HCP Vault"; \
		echo "  eval \$$(make conformance-token-env)  # pulls from HCP into shell"; \
		echo ""; \
		echo "Or set it manually:"; \
		echo "  export CONFORMANCE_TOKEN=<your-token>"; \
		exit 1; \
	fi
	CONFORMANCE_SERVER=https://www.certification.openid.net/ python conformance/run_tests.py --plan basic-rp --output conformance/results/hosted/basic-rp-latest.json --verbose
	CONFORMANCE_SERVER=https://www.certification.openid.net/ python conformance/run_tests.py --plan config-rp --output conformance/results/hosted/config-rp-latest.json --verbose
	@echo "Hosted conformance tests complete. Results in conformance/results/hosted/"

.PHONY: ci-setup
ci-setup:
	python -m pip install --upgrade pip
	pip install pipx
	pipx install uv
	uv venv
	uv sync --all-packages
