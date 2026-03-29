"""
Unit tests for async token validation.

These tests verify async-specific token validation logic including
error handling, caching, and enhanced features (leeway, multi-issuer, subject).
"""

import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import httpx
import jwt as pyjwt
import pytest
import respx

from py_identity_model.aio.token_validation import _get_jwks_response
from py_identity_model.core.models import TokenValidationConfig
from py_identity_model.exceptions import (
    ConfigurationException,
    InvalidIssuerException,
    TokenExpiredException,
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


# ============================================================================
# Async enhanced feature tests (S4: parity with sync tests)
# ============================================================================


@pytest.fixture
def rsa_keypair():
    """Generate a fresh RSA key pair for testing."""
    import base64

    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    public_key = private_key.public_key()
    pub_numbers = public_key.public_numbers()

    def _int_to_base64url(n: int, length: int) -> str:
        return (
            base64.urlsafe_b64encode(n.to_bytes(length, "big"))
            .rstrip(b"=")
            .decode()
        )

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


@pytest.fixture(autouse=True)
def _clear_jwt_cache():
    """Clear JWT decode cache between tests."""
    from py_identity_model.core.jwt_helpers import _decode_jwt_cached

    _decode_jwt_cached.cache_clear()
    yield
    _decode_jwt_cached.cache_clear()


@pytest.mark.unit
class TestAsyncLeeway:
    """Async tests for clock skew tolerance (leeway)."""

    @pytest.mark.asyncio
    async def test_expired_token_rejected_without_leeway(self, rsa_keypair):
        from py_identity_model.aio.token_validation import validate_token

        key_dict, pem = rsa_keypair
        token = _sign_jwt(
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
        from py_identity_model.aio.token_validation import validate_token

        key_dict, pem = rsa_keypair
        token = _sign_jwt(
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

        decoded = await validate_token(
            jwt=token, token_validation_config=config
        )
        assert decoded["sub"] == "user1"

    @pytest.mark.asyncio
    async def test_leeway_zero_does_not_allow_expired(self, rsa_keypair):
        from py_identity_model.aio.token_validation import validate_token

        key_dict, pem = rsa_keypair
        token = _sign_jwt(
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
        from py_identity_model.aio.token_validation import validate_token

        key_dict, pem = rsa_keypair
        token = _sign_jwt(pem, {"sub": "user1", "iss": "https://idp1.com"})

        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=["RS256"],
            issuer="https://idp1.com",
        )

        decoded = await validate_token(
            jwt=token, token_validation_config=config
        )
        assert decoded["iss"] == "https://idp1.com"

    @pytest.mark.asyncio
    async def test_list_issuer_accepts_matching(self, rsa_keypair):
        from py_identity_model.aio.token_validation import validate_token

        key_dict, pem = rsa_keypair
        token = _sign_jwt(pem, {"sub": "user1", "iss": "https://idp2.com"})

        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=["RS256"],
            issuer=["https://idp1.com", "https://idp2.com"],
        )

        decoded = await validate_token(
            jwt=token, token_validation_config=config
        )
        assert decoded["iss"] == "https://idp2.com"

    @pytest.mark.asyncio
    async def test_list_issuer_rejects_non_matching(self, rsa_keypair):
        from py_identity_model.aio.token_validation import validate_token

        key_dict, pem = rsa_keypair
        token = _sign_jwt(pem, {"sub": "user1", "iss": "https://evil.com"})

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
        from py_identity_model.aio.token_validation import validate_token

        key_dict, pem = rsa_keypair
        token = _sign_jwt(pem, {"sub": "user123", "iss": "https://test.com"})

        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=["RS256"],
            subject="user123",
        )

        decoded = await validate_token(
            jwt=token, token_validation_config=config
        )
        assert decoded["sub"] == "user123"

    @pytest.mark.asyncio
    async def test_subject_mismatch_raises(self, rsa_keypair):
        from py_identity_model.aio.token_validation import validate_token

        key_dict, pem = rsa_keypair
        token = _sign_jwt(pem, {"sub": "user123", "iss": "https://test.com"})

        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=["RS256"],
            subject="different_user",
        )

        with pytest.raises(TokenValidationException, match="Invalid subject"):
            await validate_token(jwt=token, token_validation_config=config)

    @pytest.mark.asyncio
    async def test_subject_mismatch_does_not_leak_claim_value(
        self, rsa_keypair
    ):
        """S1: Error message must NOT contain the actual sub claim value."""
        from py_identity_model.aio.token_validation import validate_token

        key_dict, pem = rsa_keypair
        secret_sub = "sensitive-user-id-12345"
        token = _sign_jwt(pem, {"sub": secret_sub, "iss": "https://test.com"})

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
        from py_identity_model.aio.token_validation import validate_token

        key_dict, pem = rsa_keypair
        token = _sign_jwt(pem, {"iss": "https://test.com"})

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
        from py_identity_model.aio.token_validation import validate_token

        key_dict, pem = rsa_keypair
        token = _sign_jwt(pem, {"sub": "anyone", "iss": "https://test.com"})

        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=["RS256"],
            subject=None,
        )

        decoded = await validate_token(
            jwt=token, token_validation_config=config
        )
        assert decoded["sub"] == "anyone"
