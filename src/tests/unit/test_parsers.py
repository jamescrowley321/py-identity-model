"""Unit tests for core parsers module."""

import base64
import json

import pytest

from py_identity_model.core.models import JsonWebKey
from py_identity_model.core.parsers import (
    extract_kid_from_jwt,
    find_key_by_kid,
    get_public_key_from_jwk,
    jwks_from_dict,
)
from py_identity_model.exceptions import TokenValidationException


class TestFindKeyByKid:
    """Tests for the find_key_by_kid function."""

    def test_find_key_by_kid_success(self):
        """Test finding a key with matching kid."""
        keys = [
            JsonWebKey(kty="RSA", kid="key1", alg="RS256", n="abc", e="def"),
            JsonWebKey(kty="RSA", kid="key2", alg="RS384", n="ghi", e="jkl"),
        ]

        key_dict, alg = find_key_by_kid("key1", keys)

        assert key_dict["kid"] == "key1"
        assert alg == "RS256"

    def test_find_key_by_kid_default_algorithm(self):
        """Test that RS256 is used as default when no alg specified."""
        keys = [
            JsonWebKey(kty="RSA", kid="key1", n="abc", e="def"),
        ]

        key_dict, alg = find_key_by_kid("key1", keys)

        assert key_dict["kid"] == "key1"
        assert alg == "RS256"

    def test_find_key_by_kid_no_keys(self):
        """Test that empty keys list raises exception."""
        with pytest.raises(TokenValidationException) as exc_info:
            find_key_by_kid("key1", [])

        assert "No keys available" in str(exc_info.value)

    def test_find_key_by_kid_no_matching_key(self):
        """Test that missing kid raises exception with available kids."""
        keys = [
            JsonWebKey(kty="RSA", kid="key1", n="abc", e="def"),
            JsonWebKey(kty="RSA", kid="key2", n="ghi", e="jkl"),
        ]

        with pytest.raises(TokenValidationException) as exc_info:
            find_key_by_kid("nonexistent", keys)

        error_msg = str(exc_info.value)
        assert "No matching kid found" in error_msg
        assert "nonexistent" in error_msg

    def test_find_key_by_kid_none_kid(self):
        """Test finding a key when kid is None."""
        keys = [
            JsonWebKey(kty="RSA", kid=None, alg="RS256", n="abc", e="def"),
        ]

        key_dict, alg = find_key_by_kid(None, keys)

        # kid is optional and may not be in the dict if None
        assert key_dict.get("kid") is None
        assert alg == "RS256"


def _create_jwt_with_kid(kid: str, alg: str = "RS256") -> str:
    """Helper to create a minimal JWT with a specific kid in the header."""
    header = {"alg": alg, "typ": "JWT", "kid": kid}
    payload = {"sub": "test"}
    # Create unsigned JWT (header.payload.signature)
    # Use compact JSON without spaces for proper JWT format
    header_b64 = (
        base64.urlsafe_b64encode(
            json.dumps(header, separators=(",", ":")).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    payload_b64 = (
        base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":")).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    # Create a fake but valid base64 signature
    fake_sig = (
        base64.urlsafe_b64encode(b"fake_signature_bytes").rstrip(b"=").decode()
    )
    return f"{header_b64}.{payload_b64}.{fake_sig}"


class TestExtractKidFromJwt:
    """Tests for the extract_kid_from_jwt function."""

    def test_extract_kid_success(self):
        """Test extracting kid from JWT header."""
        jwt = _create_jwt_with_kid("test-key-id")
        kid = extract_kid_from_jwt(jwt)
        assert kid == "test-key-id"

    def test_extract_kid_missing(self):
        """Test extracting kid when not present returns None."""
        header = {"alg": "RS256", "typ": "JWT"}
        payload = {"sub": "test"}
        header_b64 = (
            base64.urlsafe_b64encode(
                json.dumps(header, separators=(",", ":")).encode()
            )
            .rstrip(b"=")
            .decode()
        )
        payload_b64 = (
            base64.urlsafe_b64encode(
                json.dumps(payload, separators=(",", ":")).encode()
            )
            .rstrip(b"=")
            .decode()
        )
        fake_sig = base64.urlsafe_b64encode(b"fake_sig").rstrip(b"=").decode()
        jwt = f"{header_b64}.{payload_b64}.{fake_sig}"

        kid = extract_kid_from_jwt(jwt)
        assert kid is None


class TestGetPublicKeyFromJwk:
    """Tests for the get_public_key_from_jwk function."""

    def test_get_public_key_success(self):
        """Test finding matching key from JWKS."""
        jwt = _create_jwt_with_kid("key1", "RS256")
        keys = [
            JsonWebKey(kty="RSA", kid="key1", alg="RS256", n="abc", e="def"),
            JsonWebKey(kty="RSA", kid="key2", alg="RS384", n="ghi", e="jkl"),
        ]

        key = get_public_key_from_jwk(jwt, keys)

        assert key.kid == "key1"
        assert key.alg == "RS256"

    def test_get_public_key_sets_alg_from_header(self):
        """Test that alg is set from JWT header when not in key."""
        jwt = _create_jwt_with_kid("key1", "RS384")
        keys = [
            JsonWebKey(kty="RSA", kid="key1", n="abc", e="def"),  # No alg
        ]

        key = get_public_key_from_jwk(jwt, keys)

        assert key.kid == "key1"
        assert key.alg == "RS384"  # Set from JWT header

    def test_get_public_key_not_found(self):
        """Test exception when no matching key found."""
        jwt = _create_jwt_with_kid("nonexistent")
        keys = [
            JsonWebKey(kty="RSA", kid="key1", n="abc", e="def"),
        ]

        with pytest.raises(TokenValidationException) as exc_info:
            get_public_key_from_jwk(jwt, keys)

        assert "No matching kid found" in str(exc_info.value)


class TestJwksFromDict:
    """Tests for the jwks_from_dict function."""

    def test_jwks_from_dict_rsa(self):
        """Test parsing RSA key from dict."""
        key_dict = {
            "kty": "RSA",
            "kid": "test-key",
            "alg": "RS256",
            "n": "modulus",
            "e": "exponent",
        }

        jwk = jwks_from_dict(key_dict)

        assert jwk.kty == "RSA"
        assert jwk.kid == "test-key"
        assert jwk.alg == "RS256"
        assert jwk.n == "modulus"
        assert jwk.e == "exponent"

    def test_jwks_from_dict_ec(self):
        """Test parsing EC key from dict."""
        key_dict = {
            "kty": "EC",
            "kid": "ec-key",
            "crv": "P-256",
            "x": "x-coord",
            "y": "y-coord",
        }

        jwk = jwks_from_dict(key_dict)

        assert jwk.kty == "EC"
        assert jwk.kid == "ec-key"
        assert jwk.crv == "P-256"
        assert jwk.x == "x-coord"
        assert jwk.y == "y-coord"

    def test_jwks_from_dict_optional_fields(self):
        """Test that optional fields are properly handled."""
        key_dict = {
            "kty": "RSA",
            "n": "modulus",
            "e": "exponent",
            # No kid, alg, or other optional fields
        }

        jwk = jwks_from_dict(key_dict)

        assert jwk.kty == "RSA"
        assert jwk.kid is None
        assert jwk.alg is None
