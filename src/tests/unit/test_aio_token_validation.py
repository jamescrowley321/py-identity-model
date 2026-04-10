"""
Unit tests for async token validation.

These tests verify async-specific token validation logic including
error handling, TTL-based JWKS caching, signature retry on key rotation,
and enhanced features (leeway, multi-issuer, subject).
"""

import time
from unittest.mock import patch

import httpx
import pytest
import respx

from py_identity_model.aio.managed_client import AsyncHTTPClient
from py_identity_model.aio.token_validation import (
    _get_disco_response,
    clear_jwks_cache,
    validate_token,
)
from py_identity_model.core.jwt_helpers import _decode_jwt_cached
from py_identity_model.core.models import TokenValidationConfig
from py_identity_model.exceptions import (
    ConfigurationException,
    InvalidIssuerException,
    SignatureVerificationException,
    TokenExpiredException,
    TokenValidationException,
)

from .token_validation_helpers import (
    DISCO_RESPONSE_NO_JWKS,
    DISCO_RESPONSE_WITH_JWKS,
    JWKS_FETCH_AFTER_EXPIRY,
    JWKS_FETCH_WITH_RETRY,
    generate_rsa_keypair,
    sign_jwt,
)


@pytest.fixture
def rsa_keypair():
    """Generate a fresh RSA key pair for testing."""
    return generate_rsa_keypair()


@pytest.fixture(autouse=True)
def _clear_caches():
    """Clear all caches between tests."""
    _get_disco_response.cache_clear()
    clear_jwks_cache()
    _decode_jwt_cached.cache_clear()
    yield
    _get_disco_response.cache_clear()
    clear_jwks_cache()
    _decode_jwt_cached.cache_clear()


class TestAsyncTokenValidation:
    """Test async token validation functionality."""

    @pytest.mark.asyncio
    async def test_manual_validation_missing_config(self):
        """Test manual validation (perform_disco=False) with missing config."""
        validation_config = TokenValidationConfig(
            perform_disco=False,
        )

        with pytest.raises(
            ConfigurationException,
            match=r"TokenValidationConfig\.key and TokenValidationConfig\.algorithms are required",
        ):
            await validate_token(
                jwt="fake.jwt.token",
                token_validation_config=validation_config,
            )

    @pytest.mark.asyncio
    @respx.mock
    async def test_missing_jwks_uri_cached_path_raises(self):
        """Test that missing jwks_uri in discovery doc raises TokenValidationException."""
        respx.get("https://example.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_NO_JWKS)
        )

        validation_config = TokenValidationConfig(
            perform_disco=True,
            audience="test-audience",
        )

        with pytest.raises(
            TokenValidationException,
            match=r"does not contain a jwks_uri.*require_key_set",
        ):
            await validate_token(
                jwt="fake.jwt.token",
                token_validation_config=validation_config,
                disco_doc_address="https://example.com/.well-known/openid-configuration",
            )

    @pytest.mark.asyncio
    @respx.mock
    async def test_missing_jwks_uri_di_path_raises(self):
        """Test that missing jwks_uri raises TokenValidationException (DI path)."""
        respx.get("https://example.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_NO_JWKS)
        )

        validation_config = TokenValidationConfig(
            perform_disco=True,
            audience="test-audience",
        )

        async with AsyncHTTPClient() as client:
            with pytest.raises(
                TokenValidationException,
                match=r"does not contain a jwks_uri.*require_key_set",
            ):
                await validate_token(
                    jwt="fake.jwt.token",
                    token_validation_config=validation_config,
                    disco_doc_address="https://example.com/.well-known/openid-configuration",
                    http_client=client,
                )

    @pytest.mark.asyncio
    @respx.mock
    async def test_empty_string_jwks_uri_cached_path_raises(self):
        """Test that empty-string jwks_uri raises TokenValidationException."""
        disco_with_empty_jwks = {**DISCO_RESPONSE_NO_JWKS, "jwks_uri": ""}
        respx.get("https://example.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=disco_with_empty_jwks)
        )

        validation_config = TokenValidationConfig(
            perform_disco=True,
            audience="test-audience",
        )

        with pytest.raises(
            TokenValidationException,
            match=r"does not contain a jwks_uri.*require_key_set",
        ):
            await validate_token(
                jwt="fake.jwt.token",
                token_validation_config=validation_config,
                disco_doc_address="https://example.com/.well-known/openid-configuration",
            )


class TestAsyncJwksCacheTTL:
    """Test TTL-based JWKS caching in async token validation."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_jwks_cache_returns_cached_within_ttl(self, rsa_keypair):
        """JWKS is fetched once and reused within TTL."""
        key_dict, pem = rsa_keypair
        token = sign_jwt(
            pem,
            {"sub": "user1", "iss": "https://example.com"},
            headers={"kid": "test-key-1"},
        )

        respx.get("https://example.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        jwks_route = respx.get("https://example.com/jwks").mock(
            return_value=httpx.Response(200, json={"keys": [key_dict]})
        )

        config = TokenValidationConfig(
            perform_disco=True,
            audience=None,
            issuer="https://example.com",
        )

        # First call — fetches JWKS
        await validate_token(
            jwt=token,
            token_validation_config=config,
            disco_doc_address="https://example.com/.well-known/openid-configuration",
        )
        assert jwks_route.call_count == 1

        _decode_jwt_cached.cache_clear()

        # Second call — should use cached JWKS
        await validate_token(
            jwt=token,
            token_validation_config=config,
            disco_doc_address="https://example.com/.well-known/openid-configuration",
        )
        assert jwks_route.call_count == 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_jwks_cache_refetches_after_ttl_expiry(self, rsa_keypair):
        """JWKS is re-fetched when TTL expires."""
        key_dict, pem = rsa_keypair
        token = sign_jwt(
            pem,
            {"sub": "user1", "iss": "https://example.com"},
            headers={"kid": "test-key-1"},
        )

        respx.get("https://example.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        jwks_route = respx.get("https://example.com/jwks").mock(
            return_value=httpx.Response(200, json={"keys": [key_dict]})
        )

        config = TokenValidationConfig(
            perform_disco=True,
            audience=None,
            issuer="https://example.com",
        )

        # First call
        await validate_token(
            jwt=token,
            token_validation_config=config,
            disco_doc_address="https://example.com/.well-known/openid-configuration",
        )
        assert jwks_route.call_count == 1

        _decode_jwt_cached.cache_clear()

        # Simulate TTL expiry
        with patch("py_identity_model.core.jwks_cache.time") as mock_time:
            mock_time.time.return_value = time.time() + 86401

            await validate_token(
                jwt=token,
                token_validation_config=config,
                disco_doc_address="https://example.com/.well-known/openid-configuration",
            )

        assert jwks_route.call_count == JWKS_FETCH_AFTER_EXPIRY


class TestAsyncSignatureRetry:
    """Test signature verification retry with JWKS refresh."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_signature_retry_on_key_rotation(self):
        """When signature fails with cached key, refresh JWKS and retry with new key."""
        old_key_dict, _old_pem = generate_rsa_keypair()
        old_key_dict["kid"] = "rotated-key"

        new_key_dict, new_pem = generate_rsa_keypair()
        new_key_dict["kid"] = "rotated-key"

        token = sign_jwt(
            new_pem,
            {"sub": "user1", "iss": "https://example.com"},
            headers={"kid": "rotated-key"},
        )

        respx.get("https://example.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        jwks_route = respx.get("https://example.com/jwks").mock(
            side_effect=[
                httpx.Response(200, json={"keys": [old_key_dict]}),
                httpx.Response(200, json={"keys": [new_key_dict]}),
            ]
        )

        config = TokenValidationConfig(
            perform_disco=True,
            audience=None,
            issuer="https://example.com",
        )

        decoded = await validate_token(
            jwt=token,
            token_validation_config=config,
            disco_doc_address="https://example.com/.well-known/openid-configuration",
        )

        assert decoded["sub"] == "user1"
        assert jwks_route.call_count == JWKS_FETCH_WITH_RETRY

    @pytest.mark.asyncio
    @respx.mock
    async def test_signature_failure_still_raises_after_retry(self):
        """When signature fails with both old and new keys, exception is raised."""
        wrong_key1, _ = generate_rsa_keypair()
        wrong_key1["kid"] = "wrong-key"
        wrong_key2, _ = generate_rsa_keypair()
        wrong_key2["kid"] = "wrong-key"

        _, signing_pem = generate_rsa_keypair()
        token = sign_jwt(
            signing_pem,
            {"sub": "user1", "iss": "https://example.com"},
            headers={"kid": "wrong-key"},
        )

        respx.get("https://example.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        respx.get("https://example.com/jwks").mock(
            side_effect=[
                httpx.Response(200, json={"keys": [wrong_key1]}),
                httpx.Response(200, json={"keys": [wrong_key2]}),
            ]
        )

        config = TokenValidationConfig(
            perform_disco=True,
            audience=None,
            issuer="https://example.com",
        )

        with pytest.raises(SignatureVerificationException):
            await validate_token(
                jwt=token,
                token_validation_config=config,
                disco_doc_address="https://example.com/.well-known/openid-configuration",
            )

    @pytest.mark.asyncio
    @respx.mock
    async def test_di_path_does_not_retry_on_signature_failure(self):
        """DI (injected client) path does not retry — raises immediately."""
        wrong_key, _ = generate_rsa_keypair()
        wrong_key["kid"] = "wrong-key"

        _, signing_pem = generate_rsa_keypair()
        token = sign_jwt(
            signing_pem,
            {"sub": "user1", "iss": "https://example.com"},
            headers={"kid": "wrong-key"},
        )

        respx.get("https://example.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        jwks_route = respx.get("https://example.com/jwks").mock(
            return_value=httpx.Response(200, json={"keys": [wrong_key]})
        )

        config = TokenValidationConfig(
            perform_disco=True,
            audience=None,
            issuer="https://example.com",
        )

        async with AsyncHTTPClient() as client:
            with pytest.raises(SignatureVerificationException):
                await validate_token(
                    jwt=token,
                    token_validation_config=config,
                    disco_doc_address="https://example.com/.well-known/openid-configuration",
                    http_client=client,
                )

        assert jwks_route.call_count == 1


# ============================================================================
# Async enhanced feature tests (S4: parity with sync tests)
# ============================================================================


@pytest.mark.unit
class TestAsyncLeeway:
    """Async tests for clock skew tolerance (leeway)."""

    @pytest.mark.asyncio
    async def test_expired_token_rejected_without_leeway(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        token = sign_jwt(
            pem,
            {
                "sub": "user1",
                "iss": "https://test.com",
                "exp": int(time.time()) - 10,
            },
        )

        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=["RS256"],
        )

        with pytest.raises(TokenExpiredException):
            await validate_token(jwt=token, token_validation_config=config)

    @pytest.mark.asyncio
    async def test_expired_token_accepted_with_leeway(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        token = sign_jwt(
            pem,
            {
                "sub": "user1",
                "iss": "https://test.com",
                "exp": int(time.time()) - 10,
            },
        )

        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=["RS256"],
            leeway=30,
        )

        decoded = await validate_token(jwt=token, token_validation_config=config)
        assert decoded["sub"] == "user1"

    @pytest.mark.asyncio
    async def test_leeway_zero_does_not_allow_expired(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        token = sign_jwt(
            pem,
            {"sub": "user1", "exp": int(time.time()) - 5},
        )

        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=["RS256"],
            leeway=0,
        )

        with pytest.raises(TokenExpiredException):
            await validate_token(jwt=token, token_validation_config=config)


@pytest.mark.unit
class TestAsyncMultiIssuer:
    """Async tests for multiple issuer validation."""

    @pytest.mark.asyncio
    async def test_single_issuer_still_works(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        token = sign_jwt(pem, {"sub": "user1", "iss": "https://idp1.com"})

        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=["RS256"],
            issuer="https://idp1.com",
        )

        decoded = await validate_token(jwt=token, token_validation_config=config)
        assert decoded["iss"] == "https://idp1.com"

    @pytest.mark.asyncio
    async def test_list_issuer_accepts_matching(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        token = sign_jwt(pem, {"sub": "user1", "iss": "https://idp2.com"})

        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=["RS256"],
            issuer=["https://idp1.com", "https://idp2.com"],
        )

        decoded = await validate_token(jwt=token, token_validation_config=config)
        assert decoded["iss"] == "https://idp2.com"

    @pytest.mark.asyncio
    async def test_list_issuer_rejects_non_matching(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        token = sign_jwt(pem, {"sub": "user1", "iss": "https://evil.com"})

        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=["RS256"],
            issuer=["https://idp1.com", "https://idp2.com"],
        )

        with pytest.raises(InvalidIssuerException):
            await validate_token(jwt=token, token_validation_config=config)


@pytest.mark.unit
class TestAsyncSubjectValidation:
    """Async tests for subject (sub) claim validation."""

    @pytest.mark.asyncio
    async def test_subject_matches(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        token = sign_jwt(pem, {"sub": "user123", "iss": "https://test.com"})

        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=["RS256"],
            subject="user123",
        )

        decoded = await validate_token(jwt=token, token_validation_config=config)
        assert decoded["sub"] == "user123"

    @pytest.mark.asyncio
    async def test_subject_mismatch_raises(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        token = sign_jwt(pem, {"sub": "user123", "iss": "https://test.com"})

        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=["RS256"],
            subject="different_user",
        )

        with pytest.raises(TokenValidationException, match="Invalid subject"):
            await validate_token(jwt=token, token_validation_config=config)

    @pytest.mark.asyncio
    async def test_subject_mismatch_does_not_leak_claim_value(self, rsa_keypair):
        """S1: Error message must NOT contain the actual sub claim value."""
        key_dict, pem = rsa_keypair
        secret_sub = "sensitive-user-id-12345"
        token = sign_jwt(pem, {"sub": secret_sub, "iss": "https://test.com"})

        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=["RS256"],
            subject="different_user",
        )

        with pytest.raises(TokenValidationException) as exc_info:
            await validate_token(jwt=token, token_validation_config=config)
        assert secret_sub not in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_missing_sub_claim_raises(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        token = sign_jwt(pem, {"iss": "https://test.com"})

        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=["RS256"],
            subject="user123",
        )

        with pytest.raises(TokenValidationException, match="Invalid subject"):
            await validate_token(jwt=token, token_validation_config=config)

    @pytest.mark.asyncio
    async def test_subject_none_skips_validation(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        token = sign_jwt(pem, {"sub": "anyone", "iss": "https://test.com"})

        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=["RS256"],
            subject=None,
        )

        decoded = await validate_token(jwt=token, token_validation_config=config)
        assert decoded["sub"] == "anyone"
