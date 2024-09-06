
.PHONY: build-dist
build-dist:
	poetry install
	poetry build

.PHONY: upload-dist
upload-dist:
	TWINE_USERNAME="__token__" \
	TWINE_PASSWORD="${token}" \
	twine upload --verbose dist/*

.PHONY: test-upload-dist
test-upload-dist:
	TWINE_USERNAME="__token__" \
	TWINE_PASSWORD="${token}" \
	TWINE_REPOSITORY_URL="https://test.pypi.org/legacy/" \
	twine upload --verbose dist/*

.PHONY: lint
lint:
	pre-commit run -a

.PHONY: test
test:
	pytest tests

