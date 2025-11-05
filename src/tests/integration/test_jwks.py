from py_identity_model import JwksRequest, get_jwks

from .test_utils import get_config


def test_get_jwks_is_successful(env_file):
    config = get_config(env_file)
    jwks_request = JwksRequest(address=config["TEST_JWKS_ADDRESS"])
    jwks_response = get_jwks(jwks_request)
    assert jwks_response.is_successful
    assert jwks_response.keys is not None
    for key in jwks_response.keys:
        assert key.kty
        assert key.alg
        assert key.use
        assert key.kid
        assert key.n
        assert key.e

        if key.x5t:
            assert key.x5c


def test_get_jwks_fails(env_file):
    jwks_request = JwksRequest(address="https://google.com")
    jwks_response = get_jwks(jwks_request)
    assert jwks_response.is_successful is False
