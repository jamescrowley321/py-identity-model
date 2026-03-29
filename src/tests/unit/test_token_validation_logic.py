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


class TestValidateTokenConfig:
    """Test token validation configuration checks (validate_token_config)."""

    def test_empty_issuer_list_rejected(self):
        """M2: Empty issuer list must be rejected as fail-open security defect."""
        from py_identity_model.core.validators import validate_token_config

        config = TokenValidationConfig(perform_disco=True, issuer=[])
        with pytest.raises(
            ConfigurationException,
            match="issuer must not be an empty list",
        ):
            validate_token_config(config)

    def test_non_empty_issuer_list_accepted(self):
        """Issuer list with values should be accepted."""
        from py_identity_model.core.validators import validate_token_config

        config = TokenValidationConfig(
            perform_disco=True,
            issuer=["https://idp1.com", "https://idp2.com"],
        )
        # Should not raise
        validate_token_config(config)

    def test_negative_leeway_rejected(self):
        """S2: Negative leeway must be rejected."""
        from py_identity_model.core.validators import validate_token_config

        config = TokenValidationConfig(perform_disco=True, leeway=-5)
        with pytest.raises(
            ConfigurationException, match="leeway must be non-negative"
        ):
            validate_token_config(config)

    def test_infinite_leeway_rejected(self):
        """S2: Infinite leeway must be rejected."""
        import math

        from py_identity_model.core.validators import validate_token_config

        config = TokenValidationConfig(perform_disco=True, leeway=math.inf)
        with pytest.raises(
            ConfigurationException, match="leeway must be a finite number"
        ):
            validate_token_config(config)

    def test_nan_leeway_rejected(self):
        """S2: NaN leeway must be rejected."""
        import math

        from py_identity_model.core.validators import validate_token_config

        config = TokenValidationConfig(perform_disco=True, leeway=math.nan)
        with pytest.raises(
            ConfigurationException, match="leeway must be a finite number"
        ):
            validate_token_config(config)

    def test_negative_infinity_leeway_rejected(self):
        """S2: Negative infinity leeway must be rejected."""
        import math

        from py_identity_model.core.validators import validate_token_config

        config = TokenValidationConfig(perform_disco=True, leeway=-math.inf)
        with pytest.raises(ConfigurationException):
            validate_token_config(config)

    def test_zero_leeway_accepted(self):
        """S2: Zero leeway should be accepted."""
        from py_identity_model.core.validators import validate_token_config

        config = TokenValidationConfig(perform_disco=True, leeway=0)
        # Should not raise
        validate_token_config(config)

    def test_none_leeway_accepted(self):
        """S2: None leeway (default) should be accepted."""
        from py_identity_model.core.validators import validate_token_config

        config = TokenValidationConfig(perform_disco=True, leeway=None)
        # Should not raise
        validate_token_config(config)


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
