"""
Unit tests for core token validation logic.

These tests verify the shared validation logic used by both sync and async implementations.
"""

import pytest

from py_identity_model.core.models import (
    DiscoveryDocumentResponse,
    JsonWebKey,
    JwksResponse,
    TokenValidationConfig,
)
from py_identity_model.core.token_validation_logic import (
    decode_with_config,
    validate_config_for_manual_validation,
    validate_disco_response,
    validate_jwks_response,
)
from py_identity_model.exceptions import (
    ConfigurationException,
    TokenValidationException,
)


class TestValidateDiscoResponse:
    """Test discovery response validation."""

    def test_validate_disco_response_successful(self):
        """Test successful discovery response validation."""
        response = DiscoveryDocumentResponse(
            is_successful=True,
            issuer="https://example.com",
            jwks_uri="https://example.com/jwks",
            authorization_endpoint="https://example.com/authorize",
            token_endpoint="https://example.com/token",
        )
        # Should not raise
        validate_disco_response(response)

    def test_validate_disco_response_not_successful(self):
        """Test discovery response validation with error."""
        response = DiscoveryDocumentResponse(
            is_successful=False,
            error="Discovery failed",
        )
        with pytest.raises(TokenValidationException, match="Discovery failed"):
            validate_disco_response(response)

    def test_validate_disco_response_no_error_message(self):
        """Test discovery response validation with no error message."""
        response = DiscoveryDocumentResponse(
            is_successful=False,
        )
        with pytest.raises(
            TokenValidationException,
            match="Discovery document request failed",
        ):
            validate_disco_response(response)


class TestValidateJwksResponse:
    """Test JWKS response validation."""

    def test_validate_jwks_response_successful(self):
        """Test successful JWKS response validation."""
        response = JwksResponse(
            is_successful=True,
            keys=[
                JsonWebKey(
                    kty="RSA",
                    use="sig",
                    kid="test-key-1",
                    n="test-n",
                    e="AQAB",
                ),
            ],
        )
        # Should not raise
        validate_jwks_response(response)

    def test_validate_jwks_response_not_successful(self):
        """Test JWKS response validation with error."""
        response = JwksResponse(
            is_successful=False,
            error="JWKS fetch failed",
        )
        with pytest.raises(
            TokenValidationException, match="JWKS fetch failed"
        ):
            validate_jwks_response(response)

    def test_validate_jwks_response_no_error_message(self):
        """Test JWKS response validation with no error message."""
        response = JwksResponse(
            is_successful=False,
        )
        with pytest.raises(
            TokenValidationException, match="JWKS request failed"
        ):
            validate_jwks_response(response)

    def test_validate_jwks_response_no_keys(self):
        """Test JWKS response validation with no keys."""
        response = JwksResponse(
            is_successful=True,
            keys=[],
        )
        with pytest.raises(
            TokenValidationException,
            match="No keys available in JWKS response",
        ):
            validate_jwks_response(response)


class TestValidateConfigForManualValidation:
    """Test configuration validation for manual validation mode."""

    def test_validate_config_missing_key(self):
        """Test config validation with missing key."""
        config = TokenValidationConfig(
            perform_disco=False,
            algorithms=["RS256"],
        )
        with pytest.raises(
            ConfigurationException,
            match="TokenValidationConfig.key is required",
        ):
            validate_config_for_manual_validation(config)

    def test_validate_config_missing_algorithms(self):
        """Test config validation with missing algorithms."""
        config = TokenValidationConfig(
            perform_disco=False,
            key={"kty": "RSA", "n": "test", "e": "AQAB"},
        )
        with pytest.raises(
            ConfigurationException,
            match="TokenValidationConfig.algorithms is required",
        ):
            validate_config_for_manual_validation(config)

    def test_validate_config_valid(self):
        """Test config validation with valid config."""
        config = TokenValidationConfig(
            perform_disco=False,
            key={"kty": "RSA", "n": "test", "e": "AQAB"},
            algorithms=["RS256"],
        )
        # Should not raise
        validate_config_for_manual_validation(config)


class TestDecodeWithConfig:
    """Test JWT decoding with configuration."""

    def test_decode_with_config_missing_key(self):
        """Test decode with missing key."""
        config = TokenValidationConfig(
            perform_disco=False,
            algorithms=["RS256"],
        )
        with pytest.raises(
            ConfigurationException,
            match="Token validation configuration must have key and algorithms set",
        ):
            decode_with_config("fake.jwt.token", config)

    def test_decode_with_config_missing_algorithms(self):
        """Test decode with missing algorithms."""
        config = TokenValidationConfig(
            perform_disco=False,
            key={"kty": "RSA", "n": "test", "e": "AQAB"},
        )
        with pytest.raises(
            ConfigurationException,
            match="Token validation configuration must have key and algorithms set",
        ):
            decode_with_config("fake.jwt.token", config)
