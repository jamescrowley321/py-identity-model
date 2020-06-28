import os

import pytest

from py_oidc import PyOidcException, validate_token

TEST_DISCO_ADDRESS = os.environ["TEST_DISCO_ADDRESS"]
# TODO: make env variable
TEST_EXPIRED_TOKEN = os.environ["TEST_EXPIRED_TOKEN"]


def test_token_validation_expired_token():
    with pytest.raises(PyOidcException):
        validate_token(
            jwt=TEST_EXPIRED_TOKEN, disco_doc_address=TEST_DISCO_ADDRESS
        )
