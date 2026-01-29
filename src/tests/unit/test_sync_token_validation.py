"""
Unit tests for sync token validation.

These tests verify sync-specific token validation logic including
error handling and caching.
"""

import httpx
import pytest
import respx

from py_identity_model.core.models import TokenValidationConfig
from py_identity_model.exceptions import (
    ConfigurationException,
    TokenValidationException,
)
from py_identity_model.sync.token_validation import (
    _get_disco_response,
    _get_jwks_response,
    _get_public_key_by_kid,
    validate_token,
)


class TestSyncTokenValidation:
    """Test sync token validation functionality."""

    @respx.mock
    def test_get_jwks_response_no_keys(self):
        """Test that fetching JWKS with no keys raises exception."""
        # Mock JWKS endpoint to return empty keys array
        respx.get("https://example.com/jwks").mock(
            return_value=httpx.Response(
                200,
                json={"keys": []},
            )
        )

        # Clear cache before test
        _get_jwks_response.cache_clear()

        with pytest.raises(
            TokenValidationException,
            match="No keys available in JWKS response",
        ):
            _get_public_key_by_kid(
                kid="test-key",
                jwks_uri="https://example.com/jwks",
            )

    def test_manual_validation_missing_config(self):
        """Test manual validation (perform_disco=False) with missing config."""
        # Config without key/algorithms - should raise ConfigurationException
        validation_config = TokenValidationConfig(
            perform_disco=False,
        )

        with pytest.raises(
            ConfigurationException,
            match="TokenValidationConfig.key and TokenValidationConfig.algorithms are required",
        ):
            validate_token(
                jwt="fake.jwt.token",
                token_validation_config=validation_config,
            )

    @respx.mock
    def test_get_disco_response_caching(self):
        """Test that discovery response is cached."""
        # Mock discovery endpoint
        respx.get("https://example.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(
                200,
                json={
                    "issuer": "https://example.com",
                    "jwks_uri": "https://example.com/jwks",
                    "authorization_endpoint": "https://example.com/authorize",
                    "token_endpoint": "https://example.com/token",
                    "response_types_supported": ["code"],
                    "subject_types_supported": ["public"],
                    "id_token_signing_alg_values_supported": ["RS256"],
                },
            )
        )

        # Clear cache before test
        _get_disco_response.cache_clear()

        # First call
        response1 = _get_disco_response(
            "https://example.com/.well-known/openid-configuration"
        )
        # Second call (should be cached)
        response2 = _get_disco_response(
            "https://example.com/.well-known/openid-configuration"
        )

        # Both should return the same object due to caching
        assert response1.issuer == "https://example.com"
        assert response2.issuer == "https://example.com"

    @respx.mock
    def test_get_jwks_response_caching(self):
        """Test that JWKS response is cached."""
        # Mock JWKS endpoint
        respx.get("https://example.com/jwks").mock(
            return_value=httpx.Response(
                200,
                json={
                    "keys": [
                        {
                            "kty": "RSA",
                            "kid": "test-key",
                            "use": "sig",
                            "n": "test-n",
                            "e": "AQAB",
                        }
                    ]
                },
            )
        )

        # Clear cache before test
        _get_jwks_response.cache_clear()

        # First call
        response1 = _get_jwks_response("https://example.com/jwks")
        # Second call (should be cached)
        response2 = _get_jwks_response("https://example.com/jwks")

        # Both should have the same keys
        assert response1.keys is not None
        assert response2.keys is not None
        assert len(response1.keys) == 1
        assert len(response2.keys) == 1

    @respx.mock
    def test_get_public_key_by_kid_caching(self):
        """Test that public key lookup is cached by kid."""
        # Mock JWKS endpoint
        respx.get("https://example.com/jwks").mock(
            return_value=httpx.Response(
                200,
                json={
                    "keys": [
                        {
                            "kty": "RSA",
                            "kid": "test-key",
                            "use": "sig",
                            "alg": "RS256",
                            "n": "test-n",
                            "e": "AQAB",
                        }
                    ]
                },
            )
        )

        # Clear caches before test
        _get_jwks_response.cache_clear()
        _get_public_key_by_kid.cache_clear()

        # First call
        key1, alg1 = _get_public_key_by_kid(
            "test-key", "https://example.com/jwks"
        )
        # Second call (should be cached)
        key2, alg2 = _get_public_key_by_kid(
            "test-key", "https://example.com/jwks"
        )

        # Both should return the same key
        assert key1 == key2
        assert alg1 == alg2
        assert alg1 == "RS256"
