"""Unit tests for authorization callback response parsing."""

import pytest

from py_identity_model.core.authorize_response import (
    _PARAM_TO_FIELD,
    parse_authorize_callback_response,
)
from py_identity_model.exceptions import (
    AuthorizeCallbackException,
    FailedResponseAccessError,
    SuccessfulResponseAccessError,
    ValidationException,
)


CALLBACK = "https://app.example.com/callback"

# Expected token expiry values (seconds)
EXPECTED_EXPIRES_IN = 3600


@pytest.mark.unit
class TestParseAuthorizeCallbackResponse:
    """Tests for parse_authorize_callback_response."""

    def test_code_flow_query_string(self):
        response = parse_authorize_callback_response(
            f"{CALLBACK}?code=abc123&state=xyz789"
        )

        assert response.is_successful is True
        assert response.code == "abc123"
        assert response.state == "xyz789"
        assert response.values == {"code": "abc123", "state": "xyz789"}

    def test_implicit_flow_fragment(self):
        response = parse_authorize_callback_response(
            f"{CALLBACK}#access_token=token123&token_type=Bearer"
            "&state=xyz789&expires_in=3600"
        )

        assert response.is_successful is True
        assert response.access_token == "token123"
        assert response.token_type == "Bearer"
        assert response.state == "xyz789"
        assert response.expires_in == EXPECTED_EXPIRES_IN

    def test_hybrid_flow_fragment(self):
        response = parse_authorize_callback_response(
            f"{CALLBACK}#code=abc123&id_token=jwt_token&state=xyz789"
        )

        assert response.is_successful is True
        assert response.code == "abc123"
        assert response.identity_token == "jwt_token"
        assert response.state == "xyz789"

    def test_error_response(self):
        response = parse_authorize_callback_response(
            f"{CALLBACK}?error=access_denied"
            "&error_description=User+denied+access&state=xyz789"
        )

        assert response.is_successful is False
        assert response.error == "access_denied"
        assert response.error_description == "User denied access"

    def test_error_response_without_description(self):
        response = parse_authorize_callback_response(f"{CALLBACK}?error=server_error")

        assert response.is_successful is False
        assert response.error == "server_error"

    def test_fragment_takes_precedence_over_query(self):
        response = parse_authorize_callback_response(
            f"{CALLBACK}?code=query_code#code=fragment_code&state=xyz"
        )

        assert response.code == "fragment_code"
        assert response.state == "xyz"

    def test_url_encoded_values(self):
        response = parse_authorize_callback_response(
            f"{CALLBACK}?code=abc%20123&state=state%3Dwith%26special"
        )

        assert response.code == "abc 123"
        assert response.state == "state=with&special"

    def test_scope_parameter(self):
        response = parse_authorize_callback_response(
            f"{CALLBACK}#access_token=tok&scope=openid+profile+email&state=s"
        )

        assert response.scope == "openid profile email"

    def test_session_state_parameter(self):
        response = parse_authorize_callback_response(
            f"{CALLBACK}?code=abc&state=s&session_state=sess123"
        )

        assert response.session_state == "sess123"

    def test_issuer_parameter_rfc9207(self):
        response = parse_authorize_callback_response(
            f"{CALLBACK}?code=abc&state=s&iss=https%3A%2F%2Fissuer.example.com"
        )

        assert response.issuer == "https://issuer.example.com"

    def test_no_params_raises_exception(self):
        """[BH-M2] URL with no parameters must not return is_successful=True."""
        with pytest.raises(AuthorizeCallbackException, match="no callback parameters"):
            parse_authorize_callback_response(CALLBACK)

    def test_multiple_values_takes_first(self):
        response = parse_authorize_callback_response(
            f"{CALLBACK}?code=first&code=second&state=s"
        )

        assert response.code == "first"

    def test_unknown_parameters_preserved_in_values(self):
        response = parse_authorize_callback_response(
            f"{CALLBACK}?code=abc&custom_param=val&state=s"
        )

        assert response.values["custom_param"] == "val"
        assert response.code == "abc"

    def test_raw_preserved(self):
        uri = f"{CALLBACK}?code=abc&state=xyz"
        response = parse_authorize_callback_response(uri)

        assert response.raw == uri

    def test_none_input_raises_exception(self):
        """[M2] parse_authorize_callback_response(None) must not crash with TypeError."""
        with pytest.raises(AuthorizeCallbackException, match="non-empty string"):
            parse_authorize_callback_response(None)  # type: ignore

    def test_empty_string_raises_exception(self):
        """[S1] Empty redirect_uri must raise, not return misleading success."""
        with pytest.raises(AuthorizeCallbackException, match="non-empty string"):
            parse_authorize_callback_response("")

    def test_whitespace_only_raises_exception(self):
        """Whitespace-only redirect_uri must raise."""
        with pytest.raises(AuthorizeCallbackException, match="non-empty string"):
            parse_authorize_callback_response("   \t\n  ")

    def test_non_string_type_raises_exception(self):
        """Non-string types must raise, not crash with TypeError."""
        with pytest.raises(AuthorizeCallbackException, match="non-empty string"):
            parse_authorize_callback_response(12345)  # type: ignore

        with pytest.raises(AuthorizeCallbackException, match="non-empty string"):
            parse_authorize_callback_response(b"https://example.com?code=x")  # type: ignore

    def test_javascript_scheme_rejected(self):
        """[BH-S1] Dangerous URI schemes must be rejected per RFC 6749 §3.1.2.1."""
        with pytest.raises(AuthorizeCallbackException, match="http or https"):
            parse_authorize_callback_response("javascript:alert(1)?code=x&state=y")

    def test_data_scheme_rejected(self):
        with pytest.raises(AuthorizeCallbackException, match="http or https"):
            parse_authorize_callback_response("data:text/html,?code=x")

    def test_ftp_scheme_rejected(self):
        with pytest.raises(AuthorizeCallbackException, match="http or https"):
            parse_authorize_callback_response("ftp://evil.com/callback?code=x")

    def test_http_scheme_accepted(self):
        """http is allowed for localhost development."""
        response = parse_authorize_callback_response(
            "http://localhost/callback?code=abc&state=s"
        )
        assert response.code == "abc"

    def test_refresh_token_mapped(self):
        """[BH-M3] refresh_token must be mapped from callback parameters."""
        response = parse_authorize_callback_response(
            f"{CALLBACK}#access_token=tok&refresh_token=rt123&token_type=Bearer&state=s"
        )

        assert response.refresh_token == "rt123"

    def test_expires_in_as_integer(self):
        """[BH-M4] expires_in must be int per RFC 6749 §5.1."""
        response = parse_authorize_callback_response(
            f"{CALLBACK}#access_token=tok&expires_in=3600&token_type=Bearer&state=s"
        )

        assert response.expires_in == EXPECTED_EXPIRES_IN
        assert isinstance(response.expires_in, int)

    def test_expires_in_non_numeric_becomes_none(self):
        """Non-numeric expires_in is dropped rather than crashing."""
        response = parse_authorize_callback_response(
            f"{CALLBACK}#access_token=tok&expires_in=abc&token_type=Bearer&state=s"
        )

        assert response.expires_in is None

    def test_keep_blank_values_preserved(self):
        """[BH-M1] Empty parameter values are preserved (not silently dropped)."""
        response = parse_authorize_callback_response(f"{CALLBACK}?code=abc&state=")

        # Empty state is preserved in values dict (not dropped by parse_qs)
        assert "state" in response.values
        assert response.values["state"] == ""
        # Empty string is set on the response field
        assert response.state == ""

    def test_param_to_field_immutable(self):
        """[BH-S5] _PARAM_TO_FIELD must be immutable."""
        with pytest.raises(TypeError):
            _PARAM_TO_FIELD["injected"] = "field"  # type: ignore

    def test_repr_redacts_sensitive_fields(self):
        """Sensitive fields must not appear in repr output."""
        response = parse_authorize_callback_response(
            f"{CALLBACK}#access_token=secret_token&code=secret_code"
            "&state=s&token_type=Bearer"
        )
        repr_str = repr(response)

        assert "secret_token" not in repr_str
        assert "secret_code" not in repr_str
        assert "[REDACTED]" in repr_str
        assert "state='s'" in repr_str


@pytest.mark.unit
class TestAuthorizeCallbackResponseGuards:
    """Tests for _GuardedResponseMixin behavior on AuthorizeCallbackResponse."""

    def test_guarded_fields_blocked_on_error_response(self):
        response = parse_authorize_callback_response(f"{CALLBACK}?error=access_denied")

        with pytest.raises(FailedResponseAccessError, match="code"):
            _ = response.code

        with pytest.raises(FailedResponseAccessError, match="access_token"):
            _ = response.access_token

    def test_state_accessible_on_error_response(self):
        """RFC 6749 Section 4.1.2.1: state MUST be included in error responses."""
        response = parse_authorize_callback_response(
            f"{CALLBACK}?error=access_denied&state=original_state"
        )

        assert response.state == "original_state"

    def test_error_field_blocked_on_successful_response(self):
        response = parse_authorize_callback_response(f"{CALLBACK}?code=abc&state=xyz")

        with pytest.raises(SuccessfulResponseAccessError, match="error"):
            _ = response.error

    def test_error_description_blocked_on_successful_response(self):
        """[BH-S4] error_description must be guarded symmetrically with error."""
        response = parse_authorize_callback_response(f"{CALLBACK}?code=abc&state=xyz")

        with pytest.raises(SuccessfulResponseAccessError, match="error_description"):
            _ = response.error_description

    def test_error_description_accessible_on_error_response(self):
        response = parse_authorize_callback_response(
            f"{CALLBACK}?error=access_denied&error_description=denied"
        )

        assert response.error_description == "denied"

    def test_is_successful_always_accessible(self):
        success = parse_authorize_callback_response(f"{CALLBACK}?code=abc")
        error = parse_authorize_callback_response(f"{CALLBACK}?error=denied")

        assert success.is_successful is True
        assert error.is_successful is False


@pytest.mark.unit
class TestAuthorizeCallbackException:
    """Tests for AuthorizeCallbackException hierarchy."""

    def test_catchable_as_validation_exception(self):
        with pytest.raises(ValidationException):
            raise AuthorizeCallbackException("callback failed")
