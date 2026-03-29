"""Unit tests for authorization callback state validation."""

from urllib.parse import quote

import pytest

from py_identity_model.core.authorize_response import (
    AuthorizeCallbackResponse,
    parse_authorize_callback_response,
)
from py_identity_model.core.state_validation import (
    AuthorizeCallbackValidationResult,
    StateValidationResult,
    validate_authorize_callback_state,
)


CALLBACK = "https://app.example.com/callback"


def _parse(params: str) -> AuthorizeCallbackResponse:
    sep = "#" if params.startswith("#") else "?"
    return parse_authorize_callback_response(f"{CALLBACK}{sep}{params}")


@pytest.mark.unit
class TestValidateAuthorizeCallbackState:
    """Tests for validate_authorize_callback_state."""

    @pytest.mark.parametrize(
        ("params", "expected_state", "want_result"),
        [
            (
                "code=abc&state=s1",
                "s1",
                AuthorizeCallbackValidationResult.SUCCESS,
            ),
            (
                "#access_token=tok&state=s2&token_type=Bearer",
                "s2",
                AuthorizeCallbackValidationResult.SUCCESS,
            ),
            (
                f"code=c&state={'a' * 1024}",
                "a" * 1024,
                AuthorizeCallbackValidationResult.SUCCESS,
            ),
            (
                f"code=c&state={quote('abc+def/ghi=jkl&mno', safe='')}",
                "abc+def/ghi=jkl&mno",
                AuthorizeCallbackValidationResult.SUCCESS,
            ),
        ],
        ids=["code-flow", "implicit-flow", "long-state", "special-chars"],
    )
    def test_valid_state(
        self,
        params: str,
        expected_state: str,
        want_result: AuthorizeCallbackValidationResult,
    ):
        response = _parse(params)
        result = validate_authorize_callback_state(response, expected_state)

        assert result.is_valid is True
        assert result.result is want_result
        assert result.error is None

    def test_state_mismatch(self):
        result = validate_authorize_callback_state(
            _parse("code=abc&state=wrong"), "expected"
        )

        assert result.is_valid is False
        assert (
            result.result is AuthorizeCallbackValidationResult.STATE_MISMATCH
        )
        assert result.error == "state_mismatch"
        assert result.error_description is not None

    def test_missing_state(self):
        result = validate_authorize_callback_state(
            _parse("code=abc"), "expected"
        )

        assert result.is_valid is False
        assert result.result is AuthorizeCallbackValidationResult.MISSING_STATE
        assert result.error == "missing_state"

    def test_empty_state_treated_as_missing(self):
        """parse_qs drops empty values, so state='' becomes None."""
        result = validate_authorize_callback_state(
            _parse("code=c&state="), "expected"
        )

        assert result.is_valid is False
        assert result.result is AuthorizeCallbackValidationResult.MISSING_STATE

    def test_error_response_propagates_error_fields(self):
        result = validate_authorize_callback_state(
            _parse(
                "error=access_denied&error_description=User+denied&state=s"
            ),
            "s",
        )

        assert result.is_valid is False
        assert (
            result.result is AuthorizeCallbackValidationResult.ERROR_RESPONSE
        )
        assert result.error == "access_denied"
        assert result.error_description == "User denied"

    def test_error_response_takes_precedence_over_state(self):
        """Error detection runs before state comparison."""
        result = validate_authorize_callback_state(
            _parse("error=server_error"), "any"
        )

        assert (
            result.result is AuthorizeCallbackValidationResult.ERROR_RESPONSE
        )

    def test_expected_state_none_returns_missing_state(self):
        """[M1] expected_state=None must not crash with TypeError in hmac.compare_digest."""
        result = validate_authorize_callback_state(
            _parse("code=abc&state=valid"), None
        )

        assert result.is_valid is False
        assert result.result is AuthorizeCallbackValidationResult.MISSING_STATE
        assert result.error == "missing_state"
        assert result.error_description is not None
        assert "None" in result.error_description

    def test_result_dataclass_fields(self):
        """Verify StateValidationResult exposes all documented fields."""
        r = StateValidationResult(
            is_valid=False,
            result=AuthorizeCallbackValidationResult.STATE_MISMATCH,
            error="e",
            error_description="d",
        )
        assert r.is_valid is False
        assert r.error == "e"
        assert r.error_description == "d"
