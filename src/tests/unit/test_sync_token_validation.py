"""
Unit tests for sync token validation.

These tests verify sync-specific token validation logic including
error handling, TTL-based JWKS caching, and signature retry on key rotation.
"""

import base64
import time
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import httpx
import jwt as pyjwt
import pytest
import respx

from py_identity_model.core.jwt_helpers import _decode_jwt_cached
from py_identity_model.core.models import TokenValidationConfig
from py_identity_model.exceptions import (
    ConfigurationException,
    SignatureVerificationException,
    TokenValidationException,
)
from py_identity_model.sync.managed_client import HTTPClient
from py_identity_model.sync.token_validation import (
    _get_disco_response,
    clear_jwks_cache,
    validate_token,
)


# Shared discovery response without jwks_uri for testing missing-jwks_uri guards
# Expected call counts for JWKS fetch assertions
_JWKS_FETCH_AFTER_EXPIRY = 2
_JWKS_FETCH_WITH_RETRY = 2

# Shared discovery response without jwks_uri for testing missing-jwks_uri guards
_DISCO_RESPONSE_NO_JWKS = {
    "issuer": "https://example.com",
    "authorization_endpoint": "https://example.com/authorize",
    "token_endpoint": "https://example.com/token",
    "response_types_supported": ["code"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"],
}

_DISCO_RESPONSE_WITH_JWKS = {
    **_DISCO_RESPONSE_NO_JWKS,
    "jwks_uri": "https://example.com/jwks",
}


def _generate_rsa_keypair():
    """Generate an RSA key pair and return (jwk_dict, pem_bytes)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    pub_numbers = public_key.public_numbers()

    def _int_to_base64url(n: int, length: int) -> str:
        return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()

    key_dict = {
        "kty": "RSA",
        "kid": "test-key-1",
        "n": _int_to_base64url(pub_numbers.n, 256),
        "e": _int_to_base64url(pub_numbers.e, 3),
        "alg": "RS256",
        "use": "sig",
    }

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return key_dict, pem


def _sign_jwt(pem: bytes, claims: dict, headers: dict | None = None) -> str:
    """Sign a JWT with the given private key."""
    return pyjwt.encode(claims, pem, algorithm="RS256", headers=headers)


@pytest.fixture
def rsa_keypair():
    """Generate a fresh RSA key pair for testing."""
    return _generate_rsa_keypair()


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


class TestSyncTokenValidation:
    """Test sync token validation functionality."""

    def test_manual_validation_missing_config(self):
        """Test manual validation (perform_disco=False) with missing config."""
        validation_config = TokenValidationConfig(
            perform_disco=False,
        )

        with pytest.raises(
            ConfigurationException,
            match=r"TokenValidationConfig\.key and TokenValidationConfig\.algorithms are required",
        ):
            validate_token(
                jwt="fake.jwt.token",
                token_validation_config=validation_config,
            )

    @respx.mock
    def test_get_disco_response_caching(self):
        """Test that discovery response is cached."""
        respx.get("https://example.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=_DISCO_RESPONSE_WITH_JWKS)
        )

        response1 = _get_disco_response(
            "https://example.com/.well-known/openid-configuration"
        )
        response2 = _get_disco_response(
            "https://example.com/.well-known/openid-configuration"
        )

        assert response1.issuer == "https://example.com"
        assert response2.issuer == "https://example.com"

    @respx.mock
    def test_missing_jwks_uri_cached_path_raises(self):
        """Test that missing jwks_uri in discovery doc raises TokenValidationException."""
        respx.get("https://example.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=_DISCO_RESPONSE_NO_JWKS)
        )

        validation_config = TokenValidationConfig(
            perform_disco=True,
            audience="test-audience",
        )

        with pytest.raises(
            TokenValidationException,
            match=r"does not contain a jwks_uri.*require_key_set",
        ):
            validate_token(
                jwt="fake.jwt.token",
                token_validation_config=validation_config,
                disco_doc_address="https://example.com/.well-known/openid-configuration",
            )

    @respx.mock
    def test_missing_jwks_uri_di_path_raises(self):
        """Test that missing jwks_uri raises TokenValidationException (DI path)."""
        respx.get("https://example.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=_DISCO_RESPONSE_NO_JWKS)
        )

        validation_config = TokenValidationConfig(
            perform_disco=True,
            audience="test-audience",
        )

        with (
            HTTPClient() as client,
            pytest.raises(
                TokenValidationException,
                match=r"does not contain a jwks_uri.*require_key_set",
            ),
        ):
            validate_token(
                jwt="fake.jwt.token",
                token_validation_config=validation_config,
                disco_doc_address="https://example.com/.well-known/openid-configuration",
                http_client=client,
            )

    @respx.mock
    def test_empty_string_jwks_uri_cached_path_raises(self):
        """Test that empty-string jwks_uri raises TokenValidationException."""
        disco_with_empty_jwks = {**_DISCO_RESPONSE_NO_JWKS, "jwks_uri": ""}
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
            validate_token(
                jwt="fake.jwt.token",
                token_validation_config=validation_config,
                disco_doc_address="https://example.com/.well-known/openid-configuration",
            )


class TestSyncJwksCacheTTL:
    """Test TTL-based JWKS caching in sync token validation."""

    @respx.mock
    def test_jwks_cache_returns_cached_within_ttl(self, rsa_keypair):
        """JWKS is fetched once and reused within TTL."""
        key_dict, pem = rsa_keypair
        token = _sign_jwt(
            pem,
            {"sub": "user1", "iss": "https://example.com"},
            headers={"kid": "test-key-1"},
        )

        respx.get("https://example.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=_DISCO_RESPONSE_WITH_JWKS)
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
        validate_token(
            jwt=token,
            token_validation_config=config,
            disco_doc_address="https://example.com/.well-known/openid-configuration",
        )
        assert jwks_route.call_count == 1

        # Clear JWT decode cache so second call re-decodes
        _decode_jwt_cached.cache_clear()

        # Second call — should use cached JWKS (no additional fetch)
        validate_token(
            jwt=token,
            token_validation_config=config,
            disco_doc_address="https://example.com/.well-known/openid-configuration",
        )
        assert jwks_route.call_count == 1

    @respx.mock
    def test_jwks_cache_refetches_after_ttl_expiry(self, rsa_keypair):
        """JWKS is re-fetched when TTL expires."""
        key_dict, pem = rsa_keypair
        token = _sign_jwt(
            pem,
            {"sub": "user1", "iss": "https://example.com"},
            headers={"kid": "test-key-1"},
        )

        respx.get("https://example.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=_DISCO_RESPONSE_WITH_JWKS)
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
        validate_token(
            jwt=token,
            token_validation_config=config,
            disco_doc_address="https://example.com/.well-known/openid-configuration",
        )
        assert jwks_route.call_count == 1

        _decode_jwt_cached.cache_clear()

        # Simulate TTL expiry by shifting cached_at into the past
        with patch("py_identity_model.core.jwks_cache.time") as mock_time:
            mock_time.time.return_value = time.time() + 86401  # past 24h default TTL

            validate_token(
                jwt=token,
                token_validation_config=config,
                disco_doc_address="https://example.com/.well-known/openid-configuration",
            )

        # Should have fetched JWKS a second time
        assert jwks_route.call_count == _JWKS_FETCH_AFTER_EXPIRY


class TestSyncSignatureRetry:
    """Test signature verification retry with JWKS refresh."""

    @respx.mock
    def test_signature_retry_on_key_rotation(self):
        """When signature fails with cached key, refresh JWKS and retry with new key."""
        # Key 1 (old) — will be cached initially
        old_key_dict, _old_pem = _generate_rsa_keypair()
        old_key_dict["kid"] = "rotated-key"

        # Key 2 (new) — token is signed with this
        new_key_dict, new_pem = _generate_rsa_keypair()
        new_key_dict["kid"] = "rotated-key"

        token = _sign_jwt(
            new_pem,
            {"sub": "user1", "iss": "https://example.com"},
            headers={"kid": "rotated-key"},
        )

        respx.get("https://example.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=_DISCO_RESPONSE_WITH_JWKS)
        )

        # First JWKS fetch returns old key, second returns new key
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

        # Should succeed: first attempt fails with old key, retry with new key succeeds
        decoded = validate_token(
            jwt=token,
            token_validation_config=config,
            disco_doc_address="https://example.com/.well-known/openid-configuration",
        )

        assert decoded["sub"] == "user1"
        assert (
            jwks_route.call_count == _JWKS_FETCH_WITH_RETRY
        )  # initial fetch + refresh

    @respx.mock
    def test_signature_failure_still_raises_after_retry(self):
        """When signature fails with both old and new keys, exception is raised."""
        # Both keys are different from the signing key
        wrong_key1, _ = _generate_rsa_keypair()
        wrong_key1["kid"] = "wrong-key"
        wrong_key2, _ = _generate_rsa_keypair()
        wrong_key2["kid"] = "wrong-key"

        # Sign with a completely different key
        _, signing_pem = _generate_rsa_keypair()
        token = _sign_jwt(
            signing_pem,
            {"sub": "user1", "iss": "https://example.com"},
            headers={"kid": "wrong-key"},
        )

        respx.get("https://example.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=_DISCO_RESPONSE_WITH_JWKS)
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
            validate_token(
                jwt=token,
                token_validation_config=config,
                disco_doc_address="https://example.com/.well-known/openid-configuration",
            )

    @respx.mock
    def test_di_path_does_not_retry_on_signature_failure(self):
        """DI (injected client) path does not retry — raises immediately."""
        wrong_key, _ = _generate_rsa_keypair()
        wrong_key["kid"] = "wrong-key"

        _, signing_pem = _generate_rsa_keypair()
        token = _sign_jwt(
            signing_pem,
            {"sub": "user1", "iss": "https://example.com"},
            headers={"kid": "wrong-key"},
        )

        respx.get("https://example.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=_DISCO_RESPONSE_WITH_JWKS)
        )
        jwks_route = respx.get("https://example.com/jwks").mock(
            return_value=httpx.Response(200, json={"keys": [wrong_key]})
        )

        config = TokenValidationConfig(
            perform_disco=True,
            audience=None,
            issuer="https://example.com",
        )

        with HTTPClient() as client, pytest.raises(SignatureVerificationException):
            validate_token(
                jwt=token,
                token_validation_config=config,
                disco_doc_address="https://example.com/.well-known/openid-configuration",
                http_client=client,
            )

        # Only one JWKS fetch — no retry
        assert jwks_route.call_count == 1
