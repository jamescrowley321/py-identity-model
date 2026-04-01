import json

import pytest

from py_identity_model import JsonWebKey
from py_identity_model.exceptions import (
    FailedResponseAccessError,
)
from py_identity_model.jwks import JwksRequest, get_jwks, jwks_from_dict


# Minimum RSA key size (bits)
MIN_RSA_KEY_SIZE = 2048


@pytest.fixture
def jwks_data(jwks_response):
    """Pytest fixture to provide JWKS data for tests"""
    # Convert JsonWebKey objects to dictionaries
    return [jwk.as_dict() for jwk in jwks_response.keys]


def test_jwk_deserialization(jwks_data):
    """Test that each JWK in the JWKS can be deserialized correctly"""
    for jwk_dict in jwks_data:
        # Convert dict to JSON string
        jwk_json = json.dumps(jwk_dict)
        # Parse into JsonWebKey object
        jwk = JsonWebKey.from_json(jwk_json)

        # Verify required fields
        assert jwk.kty == jwk_dict["kty"]

        # Verify all fields from original are present and match
        for key, value in jwk_dict.items():
            attr_name = key.lower()
            assert hasattr(jwk, attr_name)
            assert getattr(jwk, attr_name) == value


def test_jwk_serialization(jwks_data):
    """Test that each JWK can be serialized back to JSON correctly"""
    for jwk_dict in jwks_data:
        # Convert dict to JSON string and create JsonWebKey
        jwk = JsonWebKey.from_json(json.dumps(jwk_dict))

        # Serialize back to JSON and parse to dict for comparison
        serialized = json.loads(jwk.to_json())

        # Verify all original fields are present in serialized output
        for key, value in jwk_dict.items():
            assert key in serialized
            assert serialized[key] == value


def test_jwk_roundtrip(jwks_data):
    """Test that JWK survives a roundtrip of deserialization and serialization"""
    for jwk_dict in jwks_data:
        original_json = json.dumps(jwk_dict)

        # Deserialize to JsonWebKey
        jwk = JsonWebKey.from_json(original_json)

        # Serialize back to JSON
        roundtrip_json = jwk.to_json()

        # Convert both JSONs to dicts for comparison
        original_dict = json.loads(original_json)
        roundtrip_dict = json.loads(roundtrip_json)

        assert original_dict == roundtrip_dict


def test_jwk_validation(jwks_data):
    """Test that JWK validation works correctly for different key types"""
    for jwk_dict in jwks_data:
        jwk = JsonWebKey.from_json(json.dumps(jwk_dict))

        # Test key type specific validation
        if jwk.kty == "RSA":
            assert all(hasattr(jwk, attr) for attr in ["n", "e"])
        elif jwk.kty == "EC":
            assert all(hasattr(jwk, attr) for attr in ["crv", "x", "y"])
        elif jwk.kty == "oct":
            assert hasattr(jwk, "k")


def test_key_size_calculation(jwks_data):
    """Test that key size is calculated correctly"""
    for jwk_dict in jwks_data:
        jwk = JsonWebKey.from_json(json.dumps(jwk_dict))

        # Key size should be greater than 0 for valid keys
        assert jwk.key_size > 0

        # RSA keys typically should be 2048 bits or more
        if jwk.kty == "RSA":
            assert jwk.key_size >= MIN_RSA_KEY_SIZE

        # EC keys typically use P-256 (256 bits), P-384, or P-521
        elif jwk.kty == "EC":
            assert jwk.key_size in [256, 384, 521]


def test_has_private_key(jwks_data):
    """Test private key detection"""
    for jwk_dict in jwks_data:
        jwk = JsonWebKey.from_json(json.dumps(jwk_dict))

        # Public JWKS typically don't contain private key components
        assert not jwk.has_private_key


def test_as_dict(jwks_data):
    """Test that as_dict() includes all available properties"""
    for jwk_dict in jwks_data:
        jwk = JsonWebKey.from_json(json.dumps(jwk_dict))

        # Get the dictionary representation
        jwk_as_dict = jwk.as_dict()

        # Verify all properties from the original JWK are in the dictionary
        for key, value in jwk_dict.items():
            attr_name = key.lower()
            assert attr_name in jwk_as_dict
            assert jwk_as_dict[attr_name] == value

        # Verify that all non-None properties from the JWK object are in the dictionary
        for key, value in jwk.__dict__.items():
            if value is not None:
                assert key in jwk_as_dict
                assert jwk_as_dict[key] == value


def test_jwks_from_dict_with_real_data(jwks_data):
    """Test jwks_from_dict with real JWKS data"""
    for jwk_dict in jwks_data:
        # Create JWK using jwks_from_dict
        jwk = jwks_from_dict(jwk_dict)

        # Verify required fields
        assert jwk.kty == jwk_dict["kty"]

        # Verify all fields from original dict are properly mapped
        for key, value in jwk_dict.items():
            if key == "x5t#S256":
                # Special case for x5t#S256 which maps to x5t_s256
                assert jwk.x5t_s256 == value
            else:
                attr_name = key.lower()
                assert hasattr(jwk, attr_name)
                assert getattr(jwk, attr_name) == value


def test_get_jwks_success(jwks_response):
    """Test get_jwks with successful request and key field validation."""
    assert jwks_response.is_successful is True
    assert jwks_response.keys is not None
    assert len(jwks_response.keys) > 0

    for key in jwks_response.keys:
        assert isinstance(key, JsonWebKey)
        assert key.kty is not None
        assert key.alg is not None
        assert key.use is not None
        assert key.kid is not None

        # Key-type-specific parameter checks
        if key.kty == "RSA":
            assert key.n is not None
            assert key.e is not None
        elif key.kty == "EC":
            assert key.crv is not None
            assert key.x is not None
            assert key.y is not None

        if key.x5t:
            assert key.x5c is not None


def test_get_jwks_failure():
    """Test get_jwks with failed request"""
    # Test with invalid URL
    jwks_request = JwksRequest(
        address="https://invalid-url-that-does-not-exist.com/jwks",
    )
    jwks_response = get_jwks(jwks_request)

    assert jwks_response.is_successful is False
    assert jwks_response.error is not None
    with pytest.raises(FailedResponseAccessError):
        _ = jwks_response.keys

    # Test with URL that returns non-JWKS content
    jwks_request = JwksRequest(address="https://google.com")
    jwks_response = get_jwks(jwks_request)

    assert jwks_response.is_successful is False
    assert jwks_response.error is not None
    with pytest.raises(FailedResponseAccessError):
        _ = jwks_response.keys


def test_get_jwks_network_error():
    """Test get_jwks with network errors"""
    # Test with malformed URL
    jwks_request = JwksRequest(address="not-a-valid-url")
    jwks_response = get_jwks(jwks_request)

    assert jwks_response.is_successful is False
    assert jwks_response.error is not None
    assert (
        "Network error during JWKS request" in jwks_response.error
        or "Unhandled exception during JWKS request" in jwks_response.error
    )
    with pytest.raises(FailedResponseAccessError):
        _ = jwks_response.keys
