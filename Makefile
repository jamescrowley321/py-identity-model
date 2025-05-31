$UV_PUBLISH_TOKEN=${token}
.PHONY: build-dist
build-dist:
	uv pip install -r pyproject.toml
	uv build

.PHONY: upload-dist
upload-dist:
	uv publish

.PHONY: lint
lint:
	uv run pre-commit run -a

.PHONY: test
test:
	uv run pytest src/tests

.PHONY: ci-setup
ci-setup:
	python -m pip install --upgrade pip
	pip install pipx
	pipx install uv
	uv venv
	uv ip install pre-commit
	uv pip install -r pyproject.toml


