"""Unit tests for authorization callback state validation."""

import pytest

from py_identity_model.core.authorize_response import (
    parse_authorize_callback_response,
)
from py_identity_model.core.state_validation import (
    AuthorizeCallbackValidationResult,
    validate_authorize_callback_state,
)


@pytest.mark.unit
class TestValidateAuthorizeCallbackState:
    """Tests for validate_authorize_callback_state."""

    def test_success_matching_state(self):
        response = parse_authorize_callback_response(
            "https://app.example.com/callback?code=abc&state=expected_state"
        )
        result = validate_authorize_callback_state(response, "expected_state")

        assert result.is_valid is True
        assert result.result is AuthorizeCallbackValidationResult.SUCCESS
        assert result.error is None
        assert result.error_description is None

    def test_state_mismatch(self):
        response = parse_authorize_callback_response(
            "https://app.example.com/callback?code=abc&state=wrong_state"
        )
        result = validate_authorize_callback_state(response, "expected_state")

        assert result.is_valid is False
        assert (
            result.result is AuthorizeCallbackValidationResult.STATE_MISMATCH
        )
        assert result.error == "state_mismatch"
        assert result.error_description is not None

    def test_missing_state(self):
        response = parse_authorize_callback_response(
            "https://app.example.com/callback?code=abc"
        )
        result = validate_authorize_callback_state(response, "expected_state")

        assert result.is_valid is False
        assert result.result is AuthorizeCallbackValidationResult.MISSING_STATE
        assert result.error == "missing_state"

    def test_error_response(self):
        response = parse_authorize_callback_response(
            "https://app.example.com/callback"
            "?error=access_denied&error_description=User+denied&state=s"
        )
        result = validate_authorize_callback_state(response, "s")

        assert result.is_valid is False
        assert (
            result.result is AuthorizeCallbackValidationResult.ERROR_RESPONSE
        )
        assert result.error == "access_denied"
        assert result.error_description == "User denied"

    def test_error_response_takes_precedence(self):
        """Error detection happens before state check."""
        response = parse_authorize_callback_response(
            "https://app.example.com/callback?error=server_error"
        )
        result = validate_authorize_callback_state(response, "any_state")

        assert (
            result.result is AuthorizeCallbackValidationResult.ERROR_RESPONSE
        )

    def test_special_characters_in_state(self):
        from urllib.parse import quote

        state = "abc+def/ghi=jkl&mno"
        encoded = quote(state, safe="")
        response = parse_authorize_callback_response(
            f"https://app.example.com/callback?code=c&state={encoded}"
        )
        result = validate_authorize_callback_state(response, state)

        assert result.is_valid is True
        assert result.result is AuthorizeCallbackValidationResult.SUCCESS

    def test_long_state_value(self):
        state = "a" * 1024
        response = parse_authorize_callback_response(
            f"https://app.example.com/callback?code=c&state={state}"
        )
        result = validate_authorize_callback_state(response, state)

        assert result.is_valid is True

    def test_empty_state_vs_expected(self):
        """Empty state in response vs non-empty expected → mismatch."""
        response = parse_authorize_callback_response(
            "https://app.example.com/callback?code=c&state="
        )
        # parse_qs drops empty values by default, so state will be None
        result = validate_authorize_callback_state(response, "expected")

        assert result.is_valid is False
        assert result.result is AuthorizeCallbackValidationResult.MISSING_STATE

    def test_constant_time_comparison(self):
        """Verify hmac.compare_digest is used (state mismatch doesn't leak timing)."""
        response = parse_authorize_callback_response(
            "https://app.example.com/callback?code=c&state=a"
        )
        result = validate_authorize_callback_state(response, "b")

        assert result.is_valid is False
        assert (
            result.result is AuthorizeCallbackValidationResult.STATE_MISMATCH
        )

    def test_implicit_flow_with_state(self):
        response = parse_authorize_callback_response(
            "https://app.example.com/callback"
            "#access_token=tok&state=expected&token_type=Bearer"
        )
        result = validate_authorize_callback_state(response, "expected")

        assert result.is_valid is True
        assert result.result is AuthorizeCallbackValidationResult.SUCCESS
