import pytest

from py_identity_model import PyIdentityModelException, validate_token
from .test_utils import get_config

config = get_config()
TEST_DISCO_ADDRESS = config["TEST_DISCO_ADDRESS"]
TEST_EXPIRED_TOKEN = config["TEST_EXPIRED_TOKEN"]


def test_token_validation_expired_token():
    with pytest.raises(PyIdentityModelException):
        validate_token(
            jwt=TEST_EXPIRED_TOKEN, disco_doc_address=TEST_DISCO_ADDRESS
        )


# TODO: successful token validation
