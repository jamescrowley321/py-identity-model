"""Unit tests for enhanced token validation features (leeway, multi-issuer, subject)."""

import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt as pyjwt
import pytest

from py_identity_model.core.jwt_helpers import (
    _decode_jwt_cached,
    decode_and_validate_jwt,
)
from py_identity_model.core.models import TokenValidationConfig
from py_identity_model.exceptions import (
    InvalidIssuerException,
    TokenExpiredException,
    TokenValidationException,
)


@pytest.fixture
def rsa_keypair():
    """Generate a fresh RSA key pair for testing."""
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    public_key = private_key.public_key()

    # Get public key in JWK-compatible format
    pub_numbers = public_key.public_numbers()

    import base64

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

    # PEM for signing
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
    _decode_jwt_cached.cache_clear()
    yield
    _decode_jwt_cached.cache_clear()


@pytest.mark.unit
class TestLeeway:
    """Tests for clock skew tolerance (leeway)."""

    def test_expired_token_rejected_without_leeway(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        token = _sign_jwt(
            pem,
            {
                "sub": "user1",
                "iss": "https://test.com",
                "exp": int(time.time()) - 10,
            },
        )

        with pytest.raises(TokenExpiredException):
            decode_and_validate_jwt(
                token, key_dict, ["RS256"], None, None, None
            )

    def test_expired_token_accepted_with_leeway(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        token = _sign_jwt(
            pem,
            {
                "sub": "user1",
                "iss": "https://test.com",
                "exp": int(time.time()) - 10,
            },
        )

        decoded = decode_and_validate_jwt(
            token, key_dict, ["RS256"], None, None, None, leeway=30
        )
        assert decoded["sub"] == "user1"

    def test_leeway_zero_does_not_allow_expired(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        token = _sign_jwt(
            pem,
            {"sub": "user1", "exp": int(time.time()) - 5},
        )

        with pytest.raises(TokenExpiredException):
            decode_and_validate_jwt(
                token, key_dict, ["RS256"], None, None, None, leeway=0
            )

    def test_leeway_passed_via_config(self):
        config = TokenValidationConfig(
            perform_disco=False,
            leeway=30,
        )
        assert config.leeway == 30


@pytest.mark.unit
class TestMultiIssuer:
    """Tests for multiple issuer validation."""

    def test_single_issuer_still_works(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        token = _sign_jwt(pem, {"sub": "user1", "iss": "https://idp1.com"})

        decoded = decode_and_validate_jwt(
            token, key_dict, ["RS256"], None, "https://idp1.com", None
        )
        assert decoded["iss"] == "https://idp1.com"

    def test_list_issuer_accepts_matching(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        token = _sign_jwt(pem, {"sub": "user1", "iss": "https://idp2.com"})

        decoded = decode_and_validate_jwt(
            token,
            key_dict,
            ["RS256"],
            None,
            ["https://idp1.com", "https://idp2.com"],
            None,
        )
        assert decoded["iss"] == "https://idp2.com"

    def test_list_issuer_rejects_non_matching(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        token = _sign_jwt(pem, {"sub": "user1", "iss": "https://evil.com"})

        with pytest.raises(InvalidIssuerException):
            decode_and_validate_jwt(
                token,
                key_dict,
                ["RS256"],
                None,
                ["https://idp1.com", "https://idp2.com"],
                None,
            )

    def test_config_accepts_list_issuer(self):
        config = TokenValidationConfig(
            perform_disco=False,
            issuer=["https://idp1.com", "https://idp2.com"],
        )
        assert isinstance(config.issuer, list)
        assert len(config.issuer) == 2


@pytest.mark.unit
class TestSubjectValidation:
    """Tests for subject (sub) claim validation."""

    def test_subject_matches(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        token = _sign_jwt(pem, {"sub": "user123", "iss": "https://test.com"})

        decoded = decode_and_validate_jwt(
            token, key_dict, ["RS256"], None, None, None, subject="user123"
        )
        assert decoded["sub"] == "user123"

    def test_subject_mismatch_raises(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        token = _sign_jwt(pem, {"sub": "user123", "iss": "https://test.com"})

        with pytest.raises(TokenValidationException, match="Invalid subject"):
            decode_and_validate_jwt(
                token,
                key_dict,
                ["RS256"],
                None,
                None,
                None,
                subject="different_user",
            )

    def test_missing_sub_claim_raises(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        token = _sign_jwt(pem, {"iss": "https://test.com"})

        with pytest.raises(TokenValidationException, match="Invalid subject"):
            decode_and_validate_jwt(
                token, key_dict, ["RS256"], None, None, None, subject="user123"
            )

    def test_subject_none_skips_validation(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        token = _sign_jwt(pem, {"sub": "anyone", "iss": "https://test.com"})

        decoded = decode_and_validate_jwt(
            token, key_dict, ["RS256"], None, None, None, subject=None
        )
        assert decoded["sub"] == "anyone"

    def test_config_subject_field(self):
        config = TokenValidationConfig(
            perform_disco=False,
            subject="expected_user",
        )
        assert config.subject == "expected_user"
