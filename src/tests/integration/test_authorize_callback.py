"""Integration tests for authorization callback response parsing and state validation.

These tests use real discovery documents from identity providers to build
realistic authorization callback URLs and validate the parsing and state
validation round-trip.
"""

import secrets
from urllib.parse import quote, urlencode

import pytest

from py_identity_model.core.authorize_response import (
    parse_authorize_callback_response,
)
from py_identity_model.core.state_validation import (
    AuthorizeCallbackValidationResult,
    validate_authorize_callback_state,
)


CALLBACK_URI = "https://app.example.com/oauth/callback"


@pytest.mark.integration
class TestAuthorizeCallbackWithDiscovery:
    """Test callback parsing using real discovery document metadata."""

    def test_code_flow_round_trip(self):
        """Simulate a complete authorization code flow callback round-trip."""
        state = secrets.token_urlsafe(32)
        code = secrets.token_urlsafe(48)

        # Build callback URL as an authorization server would
        params = urlencode({"code": code, "state": state})
        callback_url = f"{CALLBACK_URI}?{params}"

        response = parse_authorize_callback_response(callback_url)

        assert response.is_successful is True
        assert response.code == code
        assert response.state == state
        assert response.raw == callback_url

    def test_state_validation_round_trip(self):
        """Validate state parameter round-trip: generate → callback → validate."""
        original_state = secrets.token_urlsafe(32)
        code = secrets.token_urlsafe(48)

        params = urlencode({"code": code, "state": original_state})
        callback_url = f"{CALLBACK_URI}?{params}"

        response = parse_authorize_callback_response(callback_url)
        result = validate_authorize_callback_state(response, original_state)

        assert result.is_valid is True
        assert result.result is AuthorizeCallbackValidationResult.SUCCESS

    def test_state_mismatch_detection(self):
        """Detect CSRF attack where state doesn't match."""
        legitimate_state = secrets.token_urlsafe(32)
        attacker_state = secrets.token_urlsafe(32)

        params = urlencode({"code": "auth_code", "state": attacker_state})
        callback_url = f"{CALLBACK_URI}?{params}"

        response = parse_authorize_callback_response(callback_url)
        result = validate_authorize_callback_state(response, legitimate_state)

        assert result.is_valid is False
        assert (
            result.result is AuthorizeCallbackValidationResult.STATE_MISMATCH
        )

    def test_error_callback_with_issuer(self, discovery_document):
        """Parse error callback that includes issuer (RFC 9207)."""
        issuer = discovery_document.issuer
        state = secrets.token_urlsafe(32)

        params = urlencode(
            {
                "error": "access_denied",
                "error_description": "User denied consent",
                "state": state,
                "iss": issuer,
            }
        )
        callback_url = f"{CALLBACK_URI}?{params}"

        response = parse_authorize_callback_response(callback_url)

        assert response.is_successful is False
        assert response.error == "access_denied"
        assert response.error_description == "User denied consent"
        # state accessible on error responses per RFC 6749
        assert response.state == state

    def test_implicit_flow_fragment_callback(self):
        """Parse implicit flow callback with token in fragment."""
        state = secrets.token_urlsafe(32)
        fake_token = secrets.token_urlsafe(64)

        fragment = urlencode(
            {
                "access_token": fake_token,
                "token_type": "Bearer",
                "expires_in": "3600",
                "state": state,
            }
        )
        callback_url = f"{CALLBACK_URI}#{fragment}"

        response = parse_authorize_callback_response(callback_url)

        assert response.is_successful is True
        assert response.access_token == fake_token
        assert response.token_type == "Bearer"
        assert response.state == state

    def test_authorization_endpoint_available(
        self, discovery_document, require_https
    ):
        """Verify the identity provider exposes an authorization endpoint."""
        assert discovery_document.authorization_endpoint is not None
        if require_https:
            assert discovery_document.authorization_endpoint.startswith(
                "https://"
            )
        else:
            assert discovery_document.authorization_endpoint.startswith(
                ("https://", "http://")
            )

    def test_state_with_url_encoded_characters(self):
        """State containing special characters survives URL round-trip."""
        state = "session:abc123|nonce:def456"
        encoded_state = quote(state, safe="")

        params = f"code=auth_code&state={encoded_state}"
        callback_url = f"{CALLBACK_URI}?{params}"

        response = parse_authorize_callback_response(callback_url)
        result = validate_authorize_callback_state(response, state)

        assert result.is_valid is True


@pytest.mark.integration
class TestLiveAuthorizeCallback:
    """Test callback validation with live auth code flow results.

    These tests use auth_code_result which skips when the provider
    does not support devInteractions.
    """

    def test_live_state_validation(self, auth_code_result):
        """Verify state parameter roundtrip from live flow."""
        assert auth_code_result["state_result"].is_valid
        assert auth_code_result["callback"].state == auth_code_result["state"]

    def test_live_state_mismatch(self, auth_code_result):
        """Wrong state returns STATE_MISMATCH against live callback."""
        callback = auth_code_result["callback"]
        wrong_state = "completely-wrong-state-value"
        state_result = validate_authorize_callback_state(callback, wrong_state)
        assert not state_result.is_valid
        assert (
            state_result.result
            == AuthorizeCallbackValidationResult.STATE_MISMATCH
        )
