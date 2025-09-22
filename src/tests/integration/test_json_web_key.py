import json

import pytest
import requests
from typing import Dict, List

from py_identity_model import JsonWebKey
from py_identity_model.jwks import jwks_from_dict, get_jwks, JwksRequest
from .test_utils import get_config

TEST_JWKS_ADDRESS = get_config()["TEST_JWKS_ADDRESS"]


def fetch_jwks() -> List[Dict]:
    """Fetch JWKS from the provided URL"""
    response = requests.get(TEST_JWKS_ADDRESS)
    response.raise_for_status()
    return response.json()["keys"]


@pytest.fixture
def jwks_data():
    """Pytest fixture to provide JWKS data for tests"""
    return fetch_jwks()


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
            if isinstance(value, list):
                assert getattr(jwk, attr_name) == value
            else:
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


def test_invalid_jwk():
    """Test that invalid JWK data is handled correctly"""
    # Test missing required kty
    with pytest.raises(ValueError):
        JsonWebKey.from_json('{"kid": "test"}')

    # Test invalid JSON
    with pytest.raises(ValueError):
        JsonWebKey.from_json("{invalid json}")

    # Test empty JSON
    with pytest.raises(ValueError):
        JsonWebKey.from_json("")

    # Test None input
    with pytest.raises(ValueError):
        JsonWebKey.from_json(None)  # type: ignore


def test_key_size_calculation(jwks_data):
    """Test that key size is calculated correctly"""
    for jwk_dict in jwks_data:
        jwk = JsonWebKey.from_json(json.dumps(jwk_dict))

        # Key size should be greater than 0 for valid keys
        assert jwk.key_size > 0

        # RSA keys typically should be 2048 bits or more
        if jwk.kty == "RSA":
            assert jwk.key_size >= 2048

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


def test_jwks_from_dict_comprehensive():
    """Test that jwks_from_dict handles all JWK fields correctly"""

    # Test with a comprehensive JWK dictionary containing various fields
    test_jwk_dict = {
        # Required parameter
        "kty": "RSA",
        # Optional parameters for all keys
        "use": "sig",
        # Note: 'key_ops' is omitted as it's mutually exclusive with 'use' per RFC 7517
        "alg": "RS256",
        "kid": "test-key-id",
        # Optional JWK parameters
        "x5u": "https://example.com/cert",
        "x5c": ["MIICertificate"],
        "x5t": "thumbprint",
        "x5t#S256": "sha256-thumbprint",
        # Parameters for Elliptic Curve Keys (not used with RSA but testing)
        "crv": "P-256",
        "x": "ec-x-coordinate",
        "y": "ec-y-coordinate",
        "d": "ec-private-key",
        # Parameters for RSA Keys
        "n": "rsa-modulus",
        "e": "AQAB",
        "p": "rsa-prime-p",
        "q": "rsa-prime-q",
        "dp": "rsa-dp",
        "dq": "rsa-dq",
        "qi": "rsa-qi",
        "oth": [{"r": "additional", "d": "prime", "t": "info"}],
        # Parameters for Symmetric Keys
        "k": "symmetric-key",
    }

    # Create JWK from dictionary
    jwk = jwks_from_dict(test_jwk_dict)

    # Verify all fields are properly set
    assert jwk.kty == "RSA"
    assert jwk.use == "sig"
    assert jwk.key_ops is None  # Not set due to mutual exclusivity with 'use'
    assert jwk.alg == "RS256"
    assert jwk.kid == "test-key-id"
    assert jwk.x5u == "https://example.com/cert"
    assert jwk.x5c == ["MIICertificate"]
    assert jwk.x5t == "thumbprint"
    assert jwk.x5t_s256 == "sha256-thumbprint"
    assert jwk.crv == "P-256"
    assert jwk.x == "ec-x-coordinate"
    assert jwk.y == "ec-y-coordinate"
    assert jwk.d == "ec-private-key"
    assert jwk.n == "rsa-modulus"
    assert jwk.e == "AQAB"
    assert jwk.p == "rsa-prime-p"
    assert jwk.q == "rsa-prime-q"
    assert jwk.dp == "rsa-dp"
    assert jwk.dq == "rsa-dq"
    assert jwk.qi == "rsa-qi"
    assert jwk.oth == [{"r": "additional", "d": "prime", "t": "info"}]
    assert jwk.k == "symmetric-key"


def test_jwks_from_dict_minimal():
    """Test jwks_from_dict with minimal required fields"""
    # Test with minimal RSA JWK (only required fields)
    minimal_rsa_dict = {"kty": "RSA", "n": "modulus", "e": "AQAB"}
    rsa_jwk = jwks_from_dict(minimal_rsa_dict)

    assert rsa_jwk.kty == "RSA"
    assert rsa_jwk.n == "modulus"
    assert rsa_jwk.e == "AQAB"
    assert rsa_jwk.use is None  # Should be None for missing fields
    assert rsa_jwk.kid is None
    assert rsa_jwk.alg is None

    # Test with minimal EC JWK
    minimal_ec_dict = {"kty": "EC", "crv": "P-256", "x": "x-coord", "y": "y-coord"}
    ec_jwk = jwks_from_dict(minimal_ec_dict)

    assert ec_jwk.kty == "EC"
    assert ec_jwk.crv == "P-256"
    assert ec_jwk.x == "x-coord"
    assert ec_jwk.y == "y-coord"
    assert ec_jwk.use is None
    assert ec_jwk.kid is None

    # Test with minimal symmetric key
    minimal_oct_dict = {"kty": "oct", "k": "symmetric-key-value"}
    oct_jwk = jwks_from_dict(minimal_oct_dict)

    assert oct_jwk.kty == "oct"
    assert oct_jwk.k == "symmetric-key-value"
    assert oct_jwk.use is None
    assert oct_jwk.kid is None


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


def test_jwks_from_dict_error_handling():
    """Test jwks_from_dict error handling"""
    # Test with empty dictionary (should fail validation in JsonWebKey.__post_init__)
    with pytest.raises(
        ValueError, match="The 'kty' \\(Key Type\\) parameter is required"
    ):
        jwks_from_dict({})

    # Test with None kty
    with pytest.raises(
        ValueError, match="The 'kty' \\(Key Type\\) parameter is required"
    ):
        jwks_from_dict({"kty": None})

    # Test with invalid RSA key (missing required parameters)
    with pytest.raises(ValueError, match="RSA keys require 'n' and 'e' parameters"):
        jwks_from_dict({"kty": "RSA"})

    # Test with invalid EC key (missing required parameters)
    with pytest.raises(
        ValueError, match="EC keys require 'crv', 'x', and 'y' parameters"
    ):
        jwks_from_dict({"kty": "EC"})

    # Test with invalid symmetric key (missing required parameter)
    with pytest.raises(ValueError, match="Symmetric keys require 'k' parameter"):
        jwks_from_dict({"kty": "oct"})


def test_get_jwks_success():
    """Test get_jwks with successful request"""
    jwks_request = JwksRequest(address=TEST_JWKS_ADDRESS)
    jwks_response = get_jwks(jwks_request)

    # Verify successful response
    assert jwks_response.is_successful is True
    assert jwks_response.error is None
    assert jwks_response.keys is not None
    assert len(jwks_response.keys) > 0

    # Verify each key is a valid JsonWebKey
    for key in jwks_response.keys:
        assert isinstance(key, JsonWebKey)
        assert key.kty is not None


def test_get_jwks_failure():
    """Test get_jwks with failed request"""
    # Test with invalid URL
    jwks_request = JwksRequest(
        address="https://invalid-url-that-does-not-exist.com/jwks"
    )
    jwks_response = get_jwks(jwks_request)

    assert jwks_response.is_successful is False
    assert jwks_response.error is not None
    assert jwks_response.keys is None

    # Test with URL that returns non-JWKS content
    jwks_request = JwksRequest(address="https://google.com")
    jwks_response = get_jwks(jwks_request)

    assert jwks_response.is_successful is False
    assert jwks_response.error is not None
    assert jwks_response.keys is None


def test_get_jwks_network_error():
    """Test get_jwks with network errors"""
    # Test with malformed URL
    jwks_request = JwksRequest(address="not-a-valid-url")
    jwks_response = get_jwks(jwks_request)

    assert jwks_response.is_successful is False
    assert jwks_response.error is not None
    assert "Unhandled exception during JWKS request" in jwks_response.error
    assert jwks_response.keys is None
