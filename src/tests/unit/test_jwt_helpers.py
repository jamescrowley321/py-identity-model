"""
Unit tests for JWT helper functions.

These tests verify JWT decoding, validation, and exception handling.
"""

from jwt.exceptions import (
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidSignatureError,
    InvalidTokenError,
)
import pytest

from py_identity_model.core.jwt_helpers import decode_and_validate_jwt
from py_identity_model.exceptions import (
    InvalidAudienceException,
    InvalidIssuerException,
    SignatureVerificationException,
    TokenValidationException,
)


class TestDecodeAndValidateJWT:
    """Test JWT decoding and validation with exception handling."""

    def test_decode_jwt_invalid_audience(self, monkeypatch):
        """Test that InvalidAudienceError is converted to InvalidAudienceException."""

        def mock_decode(*args, **kwargs):
            raise InvalidAudienceError("Invalid audience")

        # Mock the internal _decode_jwt_cached function
        import py_identity_model.core.jwt_helpers

        monkeypatch.setattr(
            py_identity_model.core.jwt_helpers,
            "_decode_jwt_cached",
            mock_decode,
        )

        with pytest.raises(InvalidAudienceException, match="Invalid audience"):
            decode_and_validate_jwt(
                jwt="fake.jwt.token",
                key={"kty": "RSA", "n": "test", "e": "AQAB"},
                algorithms=["RS256"],
                audience="expected-audience",
                issuer="expected-issuer",
                options=None,
            )

    def test_decode_jwt_invalid_issuer(self, monkeypatch):
        """Test that InvalidIssuerError is converted to InvalidIssuerException."""

        def mock_decode(*args, **kwargs):
            raise InvalidIssuerError("Invalid issuer")

        import py_identity_model.core.jwt_helpers

        monkeypatch.setattr(
            py_identity_model.core.jwt_helpers,
            "_decode_jwt_cached",
            mock_decode,
        )

        with pytest.raises(InvalidIssuerException, match="Invalid issuer"):
            decode_and_validate_jwt(
                jwt="fake.jwt.token",
                key={"kty": "RSA", "n": "test", "e": "AQAB"},
                algorithms=["RS256"],
                audience="expected-audience",
                issuer="expected-issuer",
                options=None,
            )

    def test_decode_jwt_invalid_signature(self, monkeypatch):
        """Test that InvalidSignatureError is converted to SignatureVerificationException."""

        def mock_decode(*args, **kwargs):
            raise InvalidSignatureError("Invalid signature")

        import py_identity_model.core.jwt_helpers

        monkeypatch.setattr(
            py_identity_model.core.jwt_helpers,
            "_decode_jwt_cached",
            mock_decode,
        )

        with pytest.raises(
            SignatureVerificationException, match="Invalid signature"
        ):
            decode_and_validate_jwt(
                jwt="fake.jwt.token",
                key={"kty": "RSA", "n": "test", "e": "AQAB"},
                algorithms=["RS256"],
                audience=None,
                issuer=None,
                options=None,
            )

    def test_decode_jwt_invalid_token(self, monkeypatch):
        """Test that InvalidTokenError is converted to TokenValidationException."""

        def mock_decode(*args, **kwargs):
            raise InvalidTokenError("Invalid token format")

        import py_identity_model.core.jwt_helpers

        monkeypatch.setattr(
            py_identity_model.core.jwt_helpers,
            "_decode_jwt_cached",
            mock_decode,
        )

        with pytest.raises(
            TokenValidationException,
            match="Invalid token: Invalid token format",
        ):
            decode_and_validate_jwt(
                jwt="fake.jwt.token",
                key={"kty": "RSA", "n": "test", "e": "AQAB"},
                algorithms=["RS256"],
                audience=None,
                issuer=None,
                options=None,
            )
