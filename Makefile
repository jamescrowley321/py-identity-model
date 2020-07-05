

.PHONY: build-dist
build-dist:
	python setup.py sdist

.PHONY: upload-dist
upload-dist:
    TWINE_USERNAME="__token__" \
    TWINE_PASSWORD="${TWINE_PASSWORD}" \
	twine upload --verbose dist/*

.PHONY: test-upload-dist
test-upload-dist:
    TWINE_USERNAME="__token__" \
    TWINE_PASSWORD="${TWINE_PASSWORD}" \
    TWINE_REPOSITORY_URL="https://test.pypi.org/legacy/" \
    twine upload --verbose dist/*

.PHONY: lint
lint:
    black --check py_identity_model