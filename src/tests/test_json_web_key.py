import json

import pytest
import requests
from typing import Dict, List

from py_identity_model import JsonWebKey
from tests.test_utils import get_config

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
        JsonWebKey.from_json(None)


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
