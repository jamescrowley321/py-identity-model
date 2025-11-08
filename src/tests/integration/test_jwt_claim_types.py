"""
Tests for the JwtClaimTypes class
"""

import pytest

from py_identity_model.jwt_claim_types import (
    ConfirmationMethods,
    JwtClaimTypes,
    JwtTypes,
)


def test_claim_types_constants():
    """Test that the claim type constants have the correct values"""
    assert JwtClaimTypes.Subject.value == "sub"
    assert JwtClaimTypes.Name.value == "name"
    assert JwtClaimTypes.Email.value == "email"
    assert JwtClaimTypes.Role.value == "role"
    assert JwtClaimTypes.Audience.value == "aud"
    assert JwtClaimTypes.Issuer.value == "iss"
    assert JwtClaimTypes.Expiration.value == "exp"
    assert JwtClaimTypes.IssuedAt.value == "iat"


def test_jwt_types():
    """Test the JwtTypes nested class"""
    assert JwtTypes.AccessToken.value == "at+jwt"
    assert JwtTypes.DPoPProofToken.value == "dpop+jwt"

    # Test the as_media_type method
    assert JwtTypes.as_media_type("at+jwt") == "application/at+jwt"

    # Test error handling
    with pytest.raises(ValueError, match="value cannot be None or whitespace"):
        JwtTypes.as_media_type("")

    with pytest.raises(ValueError, match="value cannot be None or whitespace"):
        JwtTypes.as_media_type(None)  # type: ignore


def test_confirmation_methods():
    """Test the ConfirmationMethods nested class"""
    assert ConfirmationMethods.JsonWebKey.value == "jwk"
    assert ConfirmationMethods.JwkThumbprint.value == "jkt"
    assert ConfirmationMethods.X509ThumbprintSha256.value == "x5t#S256"
