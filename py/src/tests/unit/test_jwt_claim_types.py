"""Tests for JwtTypes behavior."""

import pytest

from py_identity_model.jwt_claim_types import (
    JwtTypes,
)


def test_jwt_types_as_media_type():
    """Test the as_media_type method behavior and error handling."""
    assert JwtTypes.as_media_type("at+jwt") == "application/at+jwt"

    with pytest.raises(ValueError, match="value cannot be None or whitespace"):
        JwtTypes.as_media_type("")

    with pytest.raises(ValueError, match="value cannot be None or whitespace"):
        JwtTypes.as_media_type(None)  # type: ignore
