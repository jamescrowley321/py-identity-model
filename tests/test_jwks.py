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
        assert key.use
        assert key.kid
        assert key.x5t
        assert key.n
        assert key.e
        assert key.x5c
        assert key.issuer


# def test_get_jwks_fails():
#     jwks_request = JwksRequest(address='htt://not.a.real.address')
#     jwks_response = get_jwks(jwks_request)
#     assert jwks_response.is_successful is False
