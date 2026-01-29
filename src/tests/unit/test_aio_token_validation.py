"""
Unit tests for async token validation.

These tests verify async-specific token validation logic including
error handling and caching.
"""

import httpx
import pytest
import respx

from py_identity_model.aio.token_validation import _get_jwks_response
from py_identity_model.core.models import TokenValidationConfig
from py_identity_model.exceptions import (
    ConfigurationException,
    TokenValidationException,
)


class TestAsyncTokenValidation:
    """Test async token validation functionality."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_get_jwks_response_no_keys(self):
        """Test that fetching JWKS with no keys raises exception."""
        from py_identity_model.aio.token_validation import (
            _get_public_key_by_kid,
        )

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
            await _get_public_key_by_kid(
                kid="test-key",
                jwks_uri="https://example.com/jwks",
            )

    @pytest.mark.asyncio
    async def test_manual_validation_missing_config(self):
        """Test manual validation (perform_disco=False) with missing config."""
        from py_identity_model.aio.token_validation import validate_token

        # Config without key/algorithms - should raise ConfigurationException
        validation_config = TokenValidationConfig(
            perform_disco=False,
        )

        with pytest.raises(
            ConfigurationException,
            match="TokenValidationConfig.key and TokenValidationConfig.algorithms are required",
        ):
            await validate_token(
                jwt="fake.jwt.token",
                token_validation_config=validation_config,
            )
