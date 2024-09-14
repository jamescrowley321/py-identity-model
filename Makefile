
.PHONY: build-dist
build-dist:
	poetry install
	poetry build

.PHONY: upload-dist
upload-dist:
	poetry config pypi-token.pypi ${token}

.PHONY: lint
lint:
	poetry run pre-commit run -a

.PHONY: test
test:
	poetry run pytest tests

.PHONY: setup
setup:
	python -m pip install --upgrade pip
	pip install pipx
	pipx install poetry
	pip install pre-commit
	pipx inject poetry poetry-plugin-export
	poetry install

