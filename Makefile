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

.PHONY: ci-setup
ci-setup:
	python -m pip install --upgrade pip
	pip install pipx
	pipx install uv
	uv venv
	uv sync --all-packages
