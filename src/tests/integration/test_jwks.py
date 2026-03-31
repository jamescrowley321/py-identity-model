import pytest

from py_identity_model import JwksRequest, get_jwks


def test_get_jwks_is_successful(jwks_response):
    """Test using cached JWKS response to avoid rate limits."""
    assert jwks_response.is_successful
    assert jwks_response.keys is not None
    for key in jwks_response.keys:
        assert key.kty
        assert key.alg
        assert key.use
        assert key.kid

        # Validate key-type-specific parameters
        if key.kty == "RSA":
            assert key.n
            assert key.e
        elif key.kty == "EC":
            assert key.crv
            assert key.x
            assert key.y

        if key.x5t:
            assert key.x5c


@pytest.mark.usefixtures("_env_file")
def test_get_jwks_fails():
    jwks_request = JwksRequest(address="https://google.com")
    jwks_response = get_jwks(jwks_request)
    assert jwks_response.is_successful is False
