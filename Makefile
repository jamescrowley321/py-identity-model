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
	uv run pytest src/tests -v

.PHONY: test-unit
test-unit:
	uv run pytest src/tests -m unit -v

.PHONY: test-integration
test-integration:
	uv run pytest src/tests -m integration -v

.PHONY: test-integration-local
test-integration-local:
	uv run pytest src/tests -m integration --env-file=.env.local -v

.PHONY: test-integration-ory
test-integration-ory:
	uv run pytest src/tests -m integration -v

.PHONY: generate-token
generate-token:
	uv run python examples/generate_token.py

.PHONY: test-examples
test-examples:
	@echo "Running example integration tests..."
	cd examples && ./run-tests.sh

.PHONY: test-all
test-all: test test-examples

.PHONY: ci-setup
ci-setup:
	python -m pip install --upgrade pip
	pip install pipx
	pipx install uv
	uv venv
	uv sync --all-packages


