"""Tests for options sanitization — prevents disabling security checks."""

import base64
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt as pyjwt
import pytest

from py_identity_model.core.jwt_helpers import (
    _sanitize_options,
    decode_and_validate_jwt,
)
from py_identity_model.exceptions import ConfigurationException


@pytest.fixture
def rsa_key_pair():
    """Generate an RSA key pair for testing."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()

    def _int_to_base64url(n):
        b = n.to_bytes((n.bit_length() + 7) // 8, byteorder="big")
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

    key_dict = {
        "kty": "RSA",
        "n": _int_to_base64url(public_numbers.n),
        "e": _int_to_base64url(public_numbers.e),
        "kid": "test-key-1",
    }

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem, key_dict


def _make_token(private_key, sub: str = "test-user") -> str:
    """Create a signed JWT."""
    now = int(time.time())
    payload = {
        "sub": sub,
        "aud": "test-aud",
        "iss": "test-iss",
        "iat": now,
        "exp": now + 3600,
    }
    return pyjwt.encode(
        payload, private_key, algorithm="RS256", headers={"kid": "test-key-1"}
    )


class TestSanitizeOptions:
    """Unit tests for _sanitize_options."""

    def test_none_options_returns_none(self):
        assert _sanitize_options(None) is None

    def test_empty_options_returns_empty(self):
        assert _sanitize_options({}) == {}

    def test_safe_options_pass_through(self):
        options = {"require": ["sub", "exp"], "strict_aud": True}
        assert _sanitize_options(options) == options

    @pytest.mark.parametrize(
        "blocked_key",
        ["verify_signature", "verify_exp", "verify_nbf", "verify_iat"],
    )
    def test_blocked_option_false_raises(self, blocked_key):
        with pytest.raises(ConfigurationException, match=blocked_key):
            _sanitize_options({blocked_key: False})

    @pytest.mark.parametrize(
        "blocked_key",
        ["verify_signature", "verify_exp", "verify_nbf", "verify_iat"],
    )
    def test_blocked_option_true_allowed(self, blocked_key):
        """Setting enforced options to True is redundant but safe."""
        result = _sanitize_options({blocked_key: True})
        assert result is not None
        assert result[blocked_key] is True

    def test_mixed_safe_and_blocked_raises(self):
        with pytest.raises(ConfigurationException, match="verify_signature"):
            _sanitize_options({"require": ["sub"], "verify_signature": False})


class TestDecodeRejectsBlockedOptions:
    """Integration tests — blocked options are rejected through the full path."""

    def test_verify_signature_false_rejected(self, rsa_key_pair):
        """Passing verify_signature=False must raise, not silently skip verification."""
        pem, key_dict = rsa_key_pair
        token = _make_token(pem)

        with pytest.raises(ConfigurationException, match="verify_signature"):
            decode_and_validate_jwt(
                jwt=token,
                key=key_dict,
                algorithms=["RS256"],
                audience="test-aud",
                issuer="test-iss",
                options={"verify_signature": False},
            )

    def test_verify_exp_false_rejected(self, rsa_key_pair):
        """Passing verify_exp=False must raise."""
        pem, key_dict = rsa_key_pair
        token = _make_token(pem)

        with pytest.raises(ConfigurationException, match="verify_exp"):
            decode_and_validate_jwt(
                jwt=token,
                key=key_dict,
                algorithms=["RS256"],
                audience="test-aud",
                issuer="test-iss",
                options={"verify_exp": False},
            )

    def test_valid_options_still_work(self, rsa_key_pair):
        """Legitimate options like require still function."""
        pem, key_dict = rsa_key_pair
        token = _make_token(pem)

        result = decode_and_validate_jwt(
            jwt=token,
            key=key_dict,
            algorithms=["RS256"],
            audience="test-aud",
            issuer="test-iss",
            options={"require": ["sub", "exp"]},
        )
        assert result["sub"] == "test-user"

    def test_no_options_works(self, rsa_key_pair):
        """Normal flow with no options continues to work."""
        pem, key_dict = rsa_key_pair
        token = _make_token(pem)

        result = decode_and_validate_jwt(
            jwt=token,
            key=key_dict,
            algorithms=["RS256"],
            audience="test-aud",
            issuer="test-iss",
            options=None,
        )
        assert result["sub"] == "test-user"
