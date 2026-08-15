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

.PHONY: test-integration-keycloak
test-integration-keycloak: ## Run integration tests against Keycloak
	@echo "Starting Keycloak fixture..."
	docker compose -f test-fixtures/keycloak/docker-compose.yml up -d --build --wait
	@echo "Running integration tests against Keycloak..."
	uv run pytest src/tests -m integration --env-file=.env.keycloak -v || \
		(docker compose -f test-fixtures/keycloak/docker-compose.yml down && exit 1)
	docker compose -f test-fixtures/keycloak/docker-compose.yml down

.PHONY: test-harness-rs
test-harness-rs: ## Boot the RS (uvicorn) against node-oidc and run the TH-1.2 real-HTTP proof
	@echo "Starting node-oidc-provider fixture..."
	docker compose -f test-fixtures/node-oidc-provider/docker-compose.yml up -d --build --wait
	@echo "Booting fastapi-identity-model RS under uvicorn (real HTTP)..."
	uv run --all-packages pytest src/tests/integration/test_rs_boot.py -m integration --env-file=.env.node-oidc -v || \
		(docker compose -f test-fixtures/node-oidc-provider/docker-compose.yml down && exit 1)
	docker compose -f test-fixtures/node-oidc-provider/docker-compose.yml down

.PHONY: test-harness-matrix
test-harness-matrix: ## Run the TH-1.3 token correctness matrix (mock-OP forged corpus + node-oidc leg) through the booted RS
	@echo "Starting node-oidc-provider fixture..."
	docker compose -f test-fixtures/node-oidc-provider/docker-compose.yml up -d --build --wait
	@echo "Running the correctness matrix through the booted RS (real HTTP)..."
	uv run --all-packages pytest src/tests/integration/test_correctness_matrix.py -m integration --env-file=.env.node-oidc -v || \
		(docker compose -f test-fixtures/node-oidc-provider/docker-compose.yml down && exit 1)
	docker compose -f test-fixtures/node-oidc-provider/docker-compose.yml down

.PHONY: test-harness-load
test-harness-load: ## Run the TH-1.5 CI-short load profile (real Locust vs the booted RS + mock OP)
	@echo "Driving the CI-short Locust profile through the booted RS (real HTTP)..."
	uv run --group load --all-packages pytest src/tests/load/test_load_ci_short.py \
		-m integration -p no:benchmark -v

.PHONY: test-harness-load-nightly
test-harness-load-nightly: ## (nightly) Long TTL-rollover / LRU-thrash / RSS-FD soak profile (S4/S7/S11/S12)
	@echo "Driving the NIGHTLY soak profile (design §4 S4/S7/S11/S12) through the booted RS..."
	uv run --group load --all-packages pytest src/tests/load/test_load_nightly.py \
		-m integration -p no:benchmark -v

.PHONY: test-harness-load-capacity
test-harness-load-capacity: ## (TH-4) Open-model ramp-to-breakpoint: find the goodput knee (C1/C2)
	@echo "Ramping arrival rate to the goodput knee (co-located = directional numbers)..."
	uv run --group load --all-packages pytest src/tests/load/test_load_capacity.py \
		-m integration -p no:benchmark -v

.PHONY: test-benchmark
test-benchmark: ## Run benchmarks
	uv run pytest src/tests/benchmarks -v --benchmark-only --benchmark-sort=name

.PHONY: test-examples
test-examples: ## Run example integration tests (Docker)
	@echo "Running example integration tests..."
	cd examples && ./run-tests.sh

.PHONY: test-all
test-all: test test-examples ## Run all tests including examples

# ── fastapi-identity-model package ───────────────────────────────────

.PHONY: test-fastapi
test-fastapi: ## Typecheck + unit-test the fastapi-identity-model package (80% coverage)
	uv sync --all-packages
	uv run --no-sync pyrefly check packages/fastapi-identity-model/fastapi_identity_model/
	uv run --no-sync pytest packages/fastapi-identity-model/tests -v -n auto -p no:benchmark \
		--cov=fastapi_identity_model --cov-report=term-missing --cov-fail-under=80

.PHONY: build-fastapi
build-fastapi: ## Build the fastapi-identity-model wheel + sdist
	uv build --package fastapi-identity-model

# ── Security gate ────────────────────────────────────────────────────

.PHONY: mutation-security
mutation-security: ## Mutation-test changed security modules vs BASE (Epic 19 G.1)
	uv run python tools/mutation_security.py

.PHONY: security-gate
security-gate: mutation-security ## Aggregate mechanical security gate (Epic 19 G.5)

# ── Pre-push ────────────────────────────────────────────────────────

.PHONY: pre-push
pre-push: lint test-fastapi test-integration-node-oidc test-integration-keycloak conformance-test-harness test-examples ## Full local validation before push

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
	@# docker --wait only checks container healthchecks; the conformance suite's
	@# TLS listener and the RP harness's /health endpoint can still be cold for
	@# several seconds after that. Poll them at the application level to match
	@# the readiness gate CI applies (.github/workflows/conformance.yml) so
	@# `make conformance-test` is not flaky from a cold start.
	@echo "Waiting for conformance suite at https://localhost.emobix.co.uk:8443..."
	@for i in $$(seq 1 60); do \
	  HTTP_CODE=$$(curl -sk -o /dev/null -w '%{http_code}' https://localhost.emobix.co.uk:8443/ || echo 000); \
	  if [ "$$HTTP_CODE" -ge 200 ] 2>/dev/null && [ "$$HTTP_CODE" -lt 400 ] 2>/dev/null; then \
	    echo "Conformance suite is ready (HTTP $$HTTP_CODE)"; \
	    break; \
	  fi; \
	  if [ "$$i" -eq 60 ]; then \
	    echo "Timed out waiting for conformance suite"; \
	    docker compose -f conformance/docker-compose.yml logs server; \
	    exit 1; \
	  fi; \
	  sleep 5; \
	done
	@echo "Waiting for RP harness at http://localhost:8888/health..."
	@for i in $$(seq 1 30); do \
	  if curl -sf http://localhost:8888/health > /dev/null 2>&1; then \
	    echo "RP harness is ready"; \
	    break; \
	  fi; \
	  if [ "$$i" -eq 30 ]; then \
	    echo "Timed out waiting for RP harness"; \
	    docker compose -f conformance/docker-compose.yml logs rp; \
	    exit 1; \
	  fi; \
	  sleep 2; \
	done
	@echo "Waiting for fastapi RP harness at http://localhost:8889/health..."
	@for i in $$(seq 1 30); do \
	  if curl -sf http://localhost:8889/health > /dev/null 2>&1; then \
	    echo "fastapi RP harness is ready"; \
	    break; \
	  fi; \
	  if [ "$$i" -eq 30 ]; then \
	    echo "Timed out waiting for fastapi RP harness"; \
	    docker compose -f conformance/docker-compose.yml logs rp-fastapi; \
	    exit 1; \
	  fi; \
	  sleep 2; \
	done

.PHONY: conformance-down
conformance-down: ## Tear down conformance suite
	docker compose -f conformance/docker-compose.yml down -v

.PHONY: conformance-test
conformance-test: $(if $(HOSTED),,conformance-up) ## Run conformance tests (HOSTED=1 for hosted suite)
ifdef HOSTED
	uv run python conformance/run_tests.py --plan basic-rp --suite-url "$(CONFORMANCE_SERVER)" --output conformance/results/hosted/basic-rp-latest.json --export-zip conformance/results/hosted/basic-rp-export.zip --rp-logs-zip conformance/results/hosted/basic-rp-rp-logs.zip --publish "$(or $(PUBLISH),none)" --verbose
	uv run python conformance/run_tests.py --plan config-rp --suite-url "$(CONFORMANCE_SERVER)" --output conformance/results/hosted/config-rp-latest.json --export-zip conformance/results/hosted/config-rp-export.zip --rp-logs-zip conformance/results/hosted/config-rp-rp-logs.zip --publish "$(or $(PUBLISH),none)" --verbose
	uv run python conformance/run_tests.py --plan form-post-basic-rp --suite-url "$(CONFORMANCE_SERVER)" --output conformance/results/hosted/form-post-basic-rp-latest.json --export-zip conformance/results/hosted/form-post-basic-rp-export.zip --rp-logs-zip conformance/results/hosted/form-post-basic-rp-rp-logs.zip --publish "$(or $(PUBLISH),none)" --verbose
	@echo "Hosted conformance tests complete. Results in conformance/results/hosted/"
else
	uv run python conformance/run_tests.py --plan basic-rp --output conformance/results/basic-rp-latest.json --verbose
	uv run python conformance/run_tests.py --plan config-rp --output conformance/results/config-rp-latest.json --verbose
	uv run python conformance/run_tests.py --plan form-post-basic-rp --output conformance/results/form-post-basic-rp-latest.json --verbose
	@echo "Conformance tests complete. Results in conformance/results/"
endif

.PHONY: conformance-test-fastapi
conformance-test-fastapi: conformance-up ## Run fastapi-identity-model package regression against the local suite
	uv run python conformance/run_tests.py --plan fastapi-basic-rp --rp-url http://localhost:8889 --output conformance/results/fastapi-basic-rp-latest.json --verbose
	uv run python conformance/run_tests.py --plan fastapi-config-rp --rp-url http://localhost:8889 --output conformance/results/fastapi-config-rp-latest.json --verbose
	uv run python conformance/run_tests.py --plan fastapi-form-post-basic-rp --rp-url http://localhost:8889 --output conformance/results/fastapi-form-post-basic-rp-latest.json --verbose
	@echo "fastapi-identity-model conformance regression complete. Results in conformance/results/"

.PHONY: conformance-test-harness
conformance-test-harness: ## Run conformance harness unit tests (parser + callback)
	uv run --with fastapi --with httpx --with python-multipart --with respx pytest conformance/tests/ -v

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
