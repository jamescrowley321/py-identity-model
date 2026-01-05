"""
Tests for token validation caching behavior and multi-token scenarios.

These tests verify:
1. Cache isolation between different providers (tokens from wrong provider fail correctly)
2. Multiple tokens from the same provider work correctly with caching
3. Benchmark accuracy with pre-generated tokens
"""

import datetime

import pytest

from py_identity_model import (
    ClientCredentialsTokenRequest,
    TokenValidationConfig,
    request_client_credentials_token,
    validate_token,
)
from py_identity_model.exceptions import TokenValidationException
from py_identity_model.sync.token_validation import (
    _get_disco_response,
    _get_jwks_response,
    _get_public_key_by_kid,
)

from .test_utils import get_alternate_provider_expired_token


# Token validation options - only override defaults where needed
DEFAULT_OPTIONS = {
    "verify_aud": False,
    "require_aud": False,
}


class TestMultipleTokensFromSameProvider:
    """Test that multiple tokens from the same provider work correctly."""

    def test_multiple_tokens_validation_succeeds(
        self, test_config, token_endpoint
    ):
        """
        Generate multiple tokens from the same provider and validate each one.

        This ensures:
        1. Each token can be validated independently
        2. Caching doesn't cause cross-token interference
        3. The cache correctly handles tokens with the same kid
        """
        # Clear caches to start fresh
        _get_disco_response.cache_clear()
        _get_jwks_response.cache_clear()
        _get_public_key_by_kid.cache_clear()

        # Generate multiple tokens
        num_tokens = 3
        tokens = []

        for i in range(num_tokens):
            response = request_client_credentials_token(
                ClientCredentialsTokenRequest(
                    client_id=test_config["TEST_CLIENT_ID"],
                    client_secret=test_config["TEST_CLIENT_SECRET"],
                    address=token_endpoint,
                    scope=test_config["TEST_SCOPE"],
                )
            )
            assert response.is_successful, f"Failed to get token {i + 1}"
            assert response.token is not None
            tokens.append(response.token["access_token"])

        # All tokens should be different (different jti claims)
        assert len(set(tokens)) == num_tokens, "Tokens should be unique"

        validation_config = TokenValidationConfig(
            perform_disco=True,
            audience=test_config["TEST_AUDIENCE"],
            options=DEFAULT_OPTIONS,
        )

        # Validate each token
        validated_claims = []
        for i, token in enumerate(tokens):
            claims = validate_token(
                jwt=token,
                disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
                token_validation_config=validation_config,
            )
            assert claims, f"Token {i + 1} validation failed"
            assert "jti" in claims, f"Token {i + 1} missing jti claim"
            validated_claims.append(claims)

        # Each token should have a unique jti
        jtis = [c["jti"] for c in validated_claims]
        assert len(set(jtis)) == num_tokens, (
            "Each token should have unique jti"
        )

        # Verify caching is working - disco and jwks should have cache hits
        disco_cache_info = _get_disco_response.cache_info()
        jwks_cache_info = _get_jwks_response.cache_info()

        # After validating 3 tokens, we should have cache hits
        # (first token causes miss, subsequent tokens hit cache)
        assert disco_cache_info.hits >= 2, "Discovery cache should have hits"
        assert jwks_cache_info.hits >= 2, "JWKS cache should have hits"


class TestCacheIsolationBetweenProviders:
    """Test that cache is properly isolated between different providers."""

    def test_wrong_provider_token_fails_validation(self, test_config):
        """
        Test that a token from one provider fails when validated
        against a different provider's discovery document.

        Uses an expired token from an alternate provider (loaded from .env.local)
        validated against the current provider's discovery endpoint.

        This ensures:
        1. Tokens are properly validated against the correct issuer
        2. Cache doesn't allow cross-provider token acceptance
        3. The kid mismatch causes proper rejection
        """
        # Get token from alternate provider (.env.local)
        alternate_provider_token = get_alternate_provider_expired_token()
        if alternate_provider_token is None:
            pytest.skip(".env.local not found - skipping cross-provider test")

        # Clear caches to ensure clean state
        _get_disco_response.cache_clear()
        _get_jwks_response.cache_clear()
        _get_public_key_by_kid.cache_clear()

        validation_config = TokenValidationConfig(
            perform_disco=True,
            audience=test_config["TEST_AUDIENCE"],
            options=DEFAULT_OPTIONS,
        )

        # Token from alternate provider should fail when validated against
        # current provider's JWKS because the kid won't match
        with pytest.raises(TokenValidationException) as exc_info:
            validate_token(
                jwt=alternate_provider_token,
                disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
                token_validation_config=validation_config,
            )

        # Should fail due to kid not found in current provider's JWKS
        error_msg = str(exc_info.value).lower()
        assert "kid" in error_msg or "key" in error_msg, (
            f"Expected kid/key mismatch error, got: {exc_info.value}"
        )
        print(
            f"Cross-provider validation correctly failed with: {exc_info.value}"
        )

    def test_expired_token_from_same_provider_fails(self, test_config):
        """
        Test that an expired token from the same provider fails with
        the correct error (expiration, not cache issues).

        This ensures the cache doesn't bypass expiration checks.
        """
        # Clear caches
        _get_disco_response.cache_clear()
        _get_jwks_response.cache_clear()
        _get_public_key_by_kid.cache_clear()

        validation_config = TokenValidationConfig(
            perform_disco=True,
            options=DEFAULT_OPTIONS,
        )

        # Use the pre-configured expired token
        from py_identity_model.exceptions import TokenExpiredException

        with pytest.raises(TokenExpiredException):
            validate_token(
                jwt=test_config["TEST_EXPIRED_TOKEN"],
                disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
                token_validation_config=validation_config,
            )


class TestBenchmarkWithPreGeneratedTokens:
    """
    Benchmark tests with pre-generated tokens for accuracy.

    Pre-generating tokens ensures the benchmark measures validation
    performance, not token generation time.
    """

    def test_benchmark_with_multiple_unique_tokens(
        self, test_config, token_endpoint
    ):
        """
        Benchmark validation with multiple unique tokens.

        This test:
        1. Pre-generates several unique tokens
        2. Validates each token multiple times
        3. Ensures the benchmark reflects real-world usage where
           different tokens are validated
        """
        # Clear caches
        _get_disco_response.cache_clear()
        _get_jwks_response.cache_clear()
        _get_public_key_by_kid.cache_clear()

        # Pre-generate tokens (this is not part of the benchmark)
        num_unique_tokens = 5
        tokens = []

        for _ in range(num_unique_tokens):
            response = request_client_credentials_token(
                ClientCredentialsTokenRequest(
                    client_id=test_config["TEST_CLIENT_ID"],
                    client_secret=test_config["TEST_CLIENT_SECRET"],
                    address=token_endpoint,
                    scope=test_config["TEST_SCOPE"],
                )
            )
            assert response.is_successful, "Failed to generate token"
            assert response.token is not None
            tokens.append(response.token["access_token"])

        validation_config = TokenValidationConfig(
            perform_disco=True,
            audience=test_config["TEST_AUDIENCE"],
            options=DEFAULT_OPTIONS,
        )

        # Warm up the cache with one validation
        validate_token(
            jwt=tokens[0],
            disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
            token_validation_config=validation_config,
        )

        # Now benchmark: validate each token multiple times
        validations_per_token = 20
        total_validations = num_unique_tokens * validations_per_token

        start_time = datetime.datetime.now(tz=datetime.UTC)

        for _ in range(validations_per_token):
            for token in tokens:
                validate_token(
                    jwt=token,
                    disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
                    token_validation_config=validation_config,
                )

        elapsed_time = datetime.datetime.now(tz=datetime.UTC) - start_time
        print(f"\n{total_validations} validations completed in {elapsed_time}")
        print(
            f"Average: {elapsed_time.total_seconds() / total_validations * 1000:.2f}ms per validation"
        )

        # 100 validations should complete in under 1 second with caching
        assert elapsed_time.total_seconds() < 1, (
            f"Benchmark too slow: {elapsed_time.total_seconds():.2f}s for "
            f"{total_validations} validations"
        )

    def test_benchmark_single_token_repeated(
        self, test_config, client_credentials_token
    ):
        """
        Benchmark validation of a single token repeated many times.

        This represents the optimal caching scenario where the same
        token is validated repeatedly (e.g., during its lifetime).
        """
        # Clear caches
        _get_disco_response.cache_clear()
        _get_jwks_response.cache_clear()
        _get_public_key_by_kid.cache_clear()

        validation_config = TokenValidationConfig(
            perform_disco=True,
            audience=test_config["TEST_AUDIENCE"],
            options=DEFAULT_OPTIONS,
        )

        token = client_credentials_token.token["access_token"]

        # Warm up
        validate_token(
            jwt=token,
            disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
            token_validation_config=validation_config,
        )

        num_validations = 100
        start_time = datetime.datetime.now(tz=datetime.UTC)

        for _ in range(num_validations):
            validate_token(
                jwt=token,
                disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
                token_validation_config=validation_config,
            )

        elapsed_time = datetime.datetime.now(tz=datetime.UTC) - start_time
        print(f"\n{num_validations} validations of same token: {elapsed_time}")
        print(
            f"Average: {elapsed_time.total_seconds() / num_validations * 1000:.2f}ms per validation"
        )

        # Single token repeated should be very fast due to full cache utilization
        assert elapsed_time.total_seconds() < 1, (
            f"Single token benchmark too slow: {elapsed_time.total_seconds():.2f}s"
        )

        # Verify cache statistics
        disco_cache_info = _get_disco_response.cache_info()
        jwks_cache_info = _get_jwks_response.cache_info()
        key_cache_info = _get_public_key_by_kid.cache_info()

        print(f"Discovery cache: {disco_cache_info}")
        print(f"JWKS cache: {jwks_cache_info}")
        print(f"Public key cache: {key_cache_info}")

        # Should have high cache hit rates
        assert disco_cache_info.hits >= num_validations - 1
        assert jwks_cache_info.hits >= num_validations - 1
