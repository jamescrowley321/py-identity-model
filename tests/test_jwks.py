import os

from py_identity_model import JwksRequest, get_jwks
from .test_utils import get_config

TEST_JWKS_ADDRESS = get_config()["TEST_JWKS_ADDRESS"]


def test_get_jwks_is_successful():
    jwks_request = JwksRequest(address=TEST_JWKS_ADDRESS)
    jwks_response = get_jwks(jwks_request)
    assert jwks_response.is_successful
    for key in jwks_response.keys:
        assert key.kty
        assert key.alg
        assert key.use
        assert key.kid
        assert key.n
        assert key.e

        if key.x5t:
            assert key.x5c


def test_get_jwks_fails():
    jwks_request = JwksRequest(address="https://google.com")
    jwks_response = get_jwks(jwks_request)
    assert jwks_response.is_successful is False
