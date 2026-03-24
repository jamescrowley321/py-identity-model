"""Unit tests for authorization callback response parsing."""

import pytest

from py_identity_model.core.authorize_response import (
    parse_authorize_callback_response,
)
from py_identity_model.exceptions import (
    AuthorizeCallbackException,
    FailedResponseAccessError,
    PyIdentityModelException,
    SuccessfulResponseAccessError,
    ValidationException,
)


CALLBACK = "https://app.example.com/callback"


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
        assert response.expires_in == "3600"

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
        response = parse_authorize_callback_response(
            f"{CALLBACK}?error=server_error"
        )

        assert response.is_successful is False
        assert response.error == "server_error"
        assert response.error_description is None

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

    def test_empty_query_and_fragment(self):
        response = parse_authorize_callback_response(CALLBACK)

        assert response.is_successful is True
        assert response.code is None
        assert response.state is None
        assert response.values == {}

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


@pytest.mark.unit
class TestAuthorizeCallbackResponseGuards:
    """Tests for _GuardedResponseMixin behavior on AuthorizeCallbackResponse."""

    def test_guarded_fields_blocked_on_error_response(self):
        response = parse_authorize_callback_response(
            f"{CALLBACK}?error=access_denied"
        )

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
        response = parse_authorize_callback_response(
            f"{CALLBACK}?code=abc&state=xyz"
        )

        with pytest.raises(SuccessfulResponseAccessError, match="error"):
            _ = response.error

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

    def test_inherits_from_validation_exception(self):
        assert isinstance(
            AuthorizeCallbackException("err"), ValidationException
        )

    def test_inherits_from_base_exception(self):
        assert isinstance(
            AuthorizeCallbackException("err"), PyIdentityModelException
        )

    def test_catchable_as_validation_exception(self):
        with pytest.raises(ValidationException):
            raise AuthorizeCallbackException("callback failed")
