import pytest

from py_identity_model.jwks import JsonWebKey, JwksRequest
from py_identity_model.jwks import JsonWebKeyParameterNames
from tests.test_json_web_key import TEST_JWKS_ADDRESS


@pytest.fixture
def jwks_url():
    """Fixture providing the JWKS endpoint URL"""
    return TEST_JWKS_ADDRESS


@pytest.fixture
def jwks_request(jwks_url):
    """Fixture providing a JwksRequest instance"""
    return JwksRequest(jwks_url)


@pytest.fixture
def jwks_data(jwks_request):
    """Fixture providing the fetched JWKS data"""
    return jwks_request.get_keys()


@pytest.fixture
def single_jwk(jwks_data):
    """Fixture providing a single JWK from the set"""
    return jwks_data[0] if jwks_data else None


def test_jwks_request_initialization(jwks_url):
    """Test JwksRequest initialization"""
    jwks_request = JwksRequest(jwks_url)
    assert jwks_request.jwks_uri == jwks_url
    assert jwks_request.keys == []


def test_jwks_request_fetch(jwks_request):
    """Test fetching JWKS from the endpoint"""
    keys = jwks_request.get_keys()
    assert isinstance(keys, list)
    assert len(keys) > 0
    assert all(isinstance(key, JsonWebKey) for key in keys)


def test_jwks_request_caching(jwks_request):
    """Test that JWKS are cached after first fetch"""
    # First fetch
    keys1 = jwks_request.get_keys()
    # Second fetch should return cached keys
    keys2 = jwks_request.get_keys()
    assert keys1 == keys2
    assert jwks_request.keys == keys1


def test_jwk_parameters(single_jwk):
    """Test JWK parameter access"""
    assert single_jwk is not None
    assert single_jwk.kty is not None
    # Test common optional parameters
    assert hasattr(single_jwk, "kid")
    assert hasattr(single_jwk, "use")
    assert hasattr(single_jwk, "alg")


def test_rsa_key_parameters(jwks_data):
    """Test RSA specific key parameters"""
    rsa_keys = [k for k in jwks_data if k.kty == "RSA"]
    for key in rsa_keys:
        assert key.n is not None  # Modulus
        assert key.e is not None  # Exponent


def test_ec_key_parameters(jwks_data):
    """Test EC specific key parameters"""
    ec_keys = [k for k in jwks_data if k.kty == "EC"]
    for key in ec_keys:
        assert key.crv is not None  # Curve
        assert key.x is not None  # X coordinate
        assert key.y is not None  # Y coordinate


def test_jwks_request_error_handling():
    """Test error handling for invalid JWKS endpoints"""
    # Test with invalid URL
    invalid_jwks_request = JwksRequest(
        "https://invalid-url.example.com/.well-known/jwks.json"
    )
    with pytest.raises(Exception):
        invalid_jwks_request.get_keys()


def test_jwks_request_with_empty_url():
    """Test JwksRequest with empty URL"""
    with pytest.raises(ValueError):
        JwksRequest("")


def test_jwks_request_with_invalid_url():
    """Test JwksRequest with invalid URL format"""
    with pytest.raises(ValueError):
        JwksRequest("not-a-url")


def test_find_key_by_kid(jwks_request, single_jwk):
    """Test finding a key by key ID"""
    if single_jwk and single_jwk.kid:
        found_key = jwks_request.find_key(single_jwk.kid)
        assert found_key is not None
        assert found_key.kid == single_jwk.kid


def test_find_nonexistent_key(jwks_request):
    """Test finding a key with non-existent key ID"""
    found_key = jwks_request.find_key("nonexistent-kid")
    assert found_key is None


def test_jwks_request_refresh(jwks_request):
    """Test refreshing the JWKS cache"""
    # Initial fetch
    initial_keys = jwks_request.get_keys()
    # Force refresh
    jwks_request.keys = []
    refreshed_keys = jwks_request.get_keys()
    assert len(refreshed_keys) > 0
    # Keys should be the same after refresh
    assert len(initial_keys) == len(refreshed_keys)


def test_key_operations_validation(jwks_data):
    """Test key operations validation"""
    for key in jwks_data:
        if hasattr(key, "_keyops") and key._keyops:
            assert isinstance(key._keyops, list)
            assert all(isinstance(op, str) for op in key._keyops)


def test_x509_certificate_handling(jwks_data):
    """Test X.509 certificate handling"""
    for key in jwks_data:
        if hasattr(key, "_certificate_clauses") and key._certificate_clauses:
            assert isinstance(key._certificate_clauses, list)
            assert all(
                isinstance(cert, str) for cert in key._certificate_clauses
            )


def test_jwk_parameter_names_enum():
    """Test JsonWebKeyParameterNames enum values"""
    assert str(JsonWebKeyParameterNames.KTY) == "kty"
    assert str(JsonWebKeyParameterNames.KID) == "kid"
    assert str(JsonWebKeyParameterNames.ALG) == "alg"
    assert str(JsonWebKeyParameterNames.USE) == "use"
    assert str(JsonWebKeyParameterNames.X5T_S256) == "x5t#S256"
