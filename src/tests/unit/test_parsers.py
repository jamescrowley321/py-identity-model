"""Unit tests for core parsers module."""

import pytest

from py_identity_model.core.models import JsonWebKey
from py_identity_model.core.parsers import find_key_by_kid
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
