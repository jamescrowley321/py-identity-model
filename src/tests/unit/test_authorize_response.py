"""Unit tests for authorization callback response parsing."""

import pytest

from py_identity_model.core.authorize_response import (
    parse_authorize_callback_response,
)
from py_identity_model.exceptions import (
    FailedResponseAccessError,
    SuccessfulResponseAccessError,
)


@pytest.mark.unit
class TestParseAuthorizeCallbackResponse:
    """Tests for parse_authorize_callback_response."""

    def test_code_flow_query_string(self):
        uri = "https://app.example.com/callback?code=abc123&state=xyz789"
        response = parse_authorize_callback_response(uri)

        assert response.is_successful is True
        assert response.code == "abc123"
        assert response.state == "xyz789"
        assert response.raw == uri
        assert response.values == {"code": "abc123", "state": "xyz789"}

    def test_implicit_flow_fragment(self):
        uri = (
            "https://app.example.com/callback"
            "#access_token=token123&token_type=Bearer&state=xyz789&expires_in=3600"
        )
        response = parse_authorize_callback_response(uri)

        assert response.is_successful is True
        assert response.access_token == "token123"
        assert response.token_type == "Bearer"
        assert response.state == "xyz789"
        assert response.expires_in == "3600"

    def test_hybrid_flow_fragment(self):
        uri = (
            "https://app.example.com/callback"
            "#code=abc123&id_token=jwt_token&state=xyz789"
        )
        response = parse_authorize_callback_response(uri)

        assert response.is_successful is True
        assert response.code == "abc123"
        assert response.identity_token == "jwt_token"
        assert response.state == "xyz789"

    def test_error_response(self):
        uri = (
            "https://app.example.com/callback"
            "?error=access_denied&error_description=User+denied+access&state=xyz789"
        )
        response = parse_authorize_callback_response(uri)

        assert response.is_successful is False
        assert response.error == "access_denied"
        assert response.error_description == "User denied access"

    def test_error_response_without_description(self):
        uri = "https://app.example.com/callback?error=server_error"
        response = parse_authorize_callback_response(uri)

        assert response.is_successful is False
        assert response.error == "server_error"
        assert response.error_description is None

    def test_fragment_takes_precedence_over_query(self):
        uri = (
            "https://app.example.com/callback"
            "?code=query_code#code=fragment_code&state=xyz"
        )
        response = parse_authorize_callback_response(uri)

        assert response.code == "fragment_code"
        assert response.state == "xyz"

    def test_url_encoded_values(self):
        uri = (
            "https://app.example.com/callback"
            "?code=abc%20123&state=state%3Dwith%26special"
        )
        response = parse_authorize_callback_response(uri)

        assert response.code == "abc 123"
        assert response.state == "state=with&special"

    def test_scope_parameter(self):
        uri = (
            "https://app.example.com/callback"
            "#access_token=tok&scope=openid+profile+email&state=s"
        )
        response = parse_authorize_callback_response(uri)

        assert response.scope == "openid profile email"

    def test_session_state_parameter(self):
        uri = (
            "https://app.example.com/callback"
            "?code=abc&state=s&session_state=sess123"
        )
        response = parse_authorize_callback_response(uri)

        assert response.session_state == "sess123"

    def test_issuer_parameter_rfc9207(self):
        uri = (
            "https://app.example.com/callback"
            "?code=abc&state=s&iss=https%3A%2F%2Fissuer.example.com"
        )
        response = parse_authorize_callback_response(uri)

        assert response.issuer == "https://issuer.example.com"

    def test_empty_query_and_fragment(self):
        uri = "https://app.example.com/callback"
        response = parse_authorize_callback_response(uri)

        assert response.is_successful is True
        assert response.code is None
        assert response.state is None
        assert response.values == {}

    def test_multiple_values_takes_first(self):
        uri = "https://app.example.com/callback?code=first&code=second&state=s"
        response = parse_authorize_callback_response(uri)

        assert response.code == "first"

    def test_unknown_parameters_in_values(self):
        uri = "https://app.example.com/callback?code=abc&custom_param=val&state=s"
        response = parse_authorize_callback_response(uri)

        assert response.values["custom_param"] == "val"
        assert response.code == "abc"

    def test_raw_preserved(self):
        uri = "https://app.example.com/callback?code=abc&state=xyz"
        response = parse_authorize_callback_response(uri)

        assert response.raw == uri


@pytest.mark.unit
class TestAuthorizeCallbackResponseGuards:
    """Tests for _GuardedResponseMixin behavior on AuthorizeCallbackResponse."""

    def test_guarded_fields_blocked_on_error_response(self):
        response = parse_authorize_callback_response(
            "https://app.example.com/callback?error=access_denied"
        )

        with pytest.raises(FailedResponseAccessError, match="code"):
            _ = response.code

        with pytest.raises(FailedResponseAccessError, match="state"):
            _ = response.state

        with pytest.raises(FailedResponseAccessError, match="access_token"):
            _ = response.access_token

    def test_error_field_blocked_on_successful_response(self):
        response = parse_authorize_callback_response(
            "https://app.example.com/callback?code=abc&state=xyz"
        )

        with pytest.raises(SuccessfulResponseAccessError, match="error"):
            _ = response.error

    def test_error_description_accessible_on_error_response(self):
        response = parse_authorize_callback_response(
            "https://app.example.com/callback"
            "?error=access_denied&error_description=denied"
        )

        assert response.error_description == "denied"

    def test_is_successful_always_accessible(self):
        success = parse_authorize_callback_response(
            "https://app.example.com/callback?code=abc"
        )
        error = parse_authorize_callback_response(
            "https://app.example.com/callback?error=denied"
        )

        assert success.is_successful is True
        assert error.is_successful is False
