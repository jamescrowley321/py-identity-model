"""
Integration tests for async token validation.

These tests verify async token validation with real tokens and async claims validators.
"""

import pytest

from py_identity_model.core.models import TokenValidationConfig
from py_identity_model.exceptions import TokenValidationException


# Token validation options - only override defaults where needed
DEFAULT_OPTIONS = {
    "verify_aud": False,  # Audience validation disabled for these tests
    "require_aud": False,
}


@pytest.mark.integration
class TestAsyncTokenValidation:
    """Test async token validation with real tokens."""

    @pytest.mark.asyncio
    async def test_async_claims_validator_success(
        self, test_config, client_credentials_token
    ):
        """Test async claims validator that succeeds."""
        from py_identity_model.aio.token_validation import validate_token

        assert client_credentials_token.token is not None

        async def async_validate_claims(token: dict):
            """Async claims validator."""
            # Validation passes

        validation_config = TokenValidationConfig(
            perform_disco=True,
            audience=test_config["TEST_AUDIENCE"],
            options=DEFAULT_OPTIONS,
            claims_validator=async_validate_claims,
        )

        decoded_token = await validate_token(
            jwt=client_credentials_token.token["access_token"],
            disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
            token_validation_config=validation_config,
        )

        assert decoded_token
        assert decoded_token["iss"]

    @pytest.mark.asyncio
    async def test_async_claims_validator_failure(
        self, test_config, client_credentials_token
    ):
        """Test async claims validator that fails."""
        from py_identity_model.aio.token_validation import validate_token

        assert client_credentials_token.token is not None

        async def async_validate_claims(token: dict):
            """Async claims validator that fails."""
            raise ValueError("Custom validation failed")

        validation_config = TokenValidationConfig(
            perform_disco=True,
            audience=test_config["TEST_AUDIENCE"],
            options=DEFAULT_OPTIONS,
            claims_validator=async_validate_claims,
        )

        with pytest.raises(
            TokenValidationException, match="Claims validation failed"
        ):
            await validate_token(
                jwt=client_credentials_token.token["access_token"],
                disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
                token_validation_config=validation_config,
            )

    @pytest.mark.asyncio
    async def test_sync_claims_validator_in_async_context(
        self, test_config, client_credentials_token
    ):
        """Test that sync claims validator works in async validation."""
        from py_identity_model.aio.token_validation import validate_token

        assert client_credentials_token.token is not None

        def sync_validate_claims(token: dict):
            """Sync claims validator."""
            # Validation passes

        validation_config = TokenValidationConfig(
            perform_disco=True,
            audience=test_config["TEST_AUDIENCE"],
            options=DEFAULT_OPTIONS,
            claims_validator=sync_validate_claims,
        )

        decoded_token = await validate_token(
            jwt=client_credentials_token.token["access_token"],
            disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
            token_validation_config=validation_config,
        )

        assert decoded_token
        assert decoded_token["iss"]
