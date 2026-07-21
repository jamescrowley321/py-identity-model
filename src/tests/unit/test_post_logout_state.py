"""Unit tests for the RP-Initiated Logout post-logout ``state`` check.

Covers OpenID Connect RP-Initiated Logout 1.0 §2 (LOGOUT-003).
"""

import pytest

from py_identity_model import (
    LogoutStateValidationException,
)
from py_identity_model import (
    validate_post_logout_state as validate_post_logout_state_top,
)
from py_identity_model.aio import (
    validate_post_logout_state as validate_post_logout_state_aio,
)
from py_identity_model.core.logout_logic import validate_post_logout_state
from py_identity_model.exceptions import (
    TokenValidationException,
    ValidationException,
)
from py_identity_model.sync import (
    validate_post_logout_state as validate_post_logout_state_sync,
)


@pytest.mark.unit
class TestValidatePostLogoutState:
    def test_matching_state_returns_none(self):
        # LOGOUT-003: matching state round-trip -> no error.
        assert validate_post_logout_state("csrf_token", "csrf_token") is None

    def test_mismatched_state_raises(self):
        # LOGOUT-003: state mismatch raises.
        with pytest.raises(LogoutStateValidationException, match="does not match"):
            validate_post_logout_state("expected", "tampered")

    def test_missing_returned_state_raises(self):
        # LOGOUT-003: no state returned to post-logout redirect raises.
        with pytest.raises(LogoutStateValidationException, match="not present"):
            validate_post_logout_state("expected", None)

    def test_empty_returned_state_raises(self):
        with pytest.raises(LogoutStateValidationException, match="not present"):
            validate_post_logout_state("expected", "")

    def test_missing_expected_state_raises(self):
        with pytest.raises(LogoutStateValidationException, match="missing or empty"):
            validate_post_logout_state(None, "returned")

    def test_empty_expected_state_raises(self):
        with pytest.raises(LogoutStateValidationException, match="missing or empty"):
            validate_post_logout_state("", "returned")

    def test_exception_is_validation_exception_not_token(self):
        # State mismatch is a CSRF/callback error, not a JWT/token error.
        exc = LogoutStateValidationException("x")
        assert isinstance(exc, ValidationException)
        assert not isinstance(exc, TokenValidationException)

    def test_public_export_identity(self):
        # Same pure function is exported from every surface (sync/aio parity).
        assert validate_post_logout_state_top is validate_post_logout_state
        assert validate_post_logout_state_sync is validate_post_logout_state
        assert validate_post_logout_state_aio is validate_post_logout_state
