"""Integration tests for authorization callback response parsing and state validation.

These tests use real discovery documents from identity providers to validate
callback parsing with live provider metadata.
"""

import secrets
from urllib.parse import urlencode

import pytest

from py_identity_model.core.authorize_response import (
    parse_authorize_callback_response,
)
from py_identity_model.core.state_validation import (
    AuthorizeCallbackValidationResult,
    validate_authorize_callback_issuer,
    validate_authorize_callback_state,
)


CALLBACK_URI = "https://app.example.com/oauth/callback"


@pytest.mark.integration
class TestAuthorizeCallbackWithDiscovery:
    """Test callback parsing using real discovery document metadata."""

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

    def test_authorization_endpoint_available(self, discovery_document, require_https):
        """Verify the identity provider exposes an authorization endpoint."""
        assert discovery_document.authorization_endpoint is not None
        if require_https:
            assert discovery_document.authorization_endpoint.startswith("https://")
        else:
            assert discovery_document.authorization_endpoint.startswith(
                ("https://", "http://")
            )

    def test_issuer_validation_with_discovery_metadata(self, discovery_document):
        """RFC 9207: a matching iss validates against the real discovery issuer.

        Drives enforcement from the live
        ``authorization_response_iss_parameter_supported`` metadata flag.
        """
        issuer = discovery_document.issuer
        state = secrets.token_urlsafe(32)
        params = urlencode({"code": "abc", "state": state, "iss": issuer})
        callback = parse_authorize_callback_response(f"{CALLBACK_URI}?{params}")

        result = validate_authorize_callback_issuer(
            callback,
            issuer,
            iss_parameter_supported=bool(
                discovery_document.authorization_response_iss_parameter_supported
            ),
        )

        assert result.is_valid is True
        assert result.result is AuthorizeCallbackValidationResult.SUCCESS

    def test_issuer_mismatch_with_discovery_metadata(self, discovery_document):
        """A mismatched iss is rejected against the real issuer (mix-up defense)."""
        state = secrets.token_urlsafe(32)
        params = urlencode(
            {"code": "abc", "state": state, "iss": "https://attacker.example.com"}
        )
        callback = parse_authorize_callback_response(f"{CALLBACK_URI}?{params}")

        result = validate_authorize_callback_issuer(callback, discovery_document.issuer)

        assert result.is_valid is False
        assert result.result is AuthorizeCallbackValidationResult.ISSUER_MISMATCH

    def test_missing_issuer_detected_when_expected(self, discovery_document):
        """RFC 9207: an absent iss is rejected when enforcement is expected.

        A callback with no ``iss`` must fail with ``MISSING_ISSUER`` when the
        client requires it (strict opt-in) and, independently, when driven
        from the AS's advertised metadata flag. Exercises AC-9 (detection of
        missing iss when expected) against the real discovery issuer.
        """
        issuer = discovery_document.issuer
        state = secrets.token_urlsafe(32)
        # Deliberately omit ``iss`` from the callback.
        params = urlencode({"code": "abc", "state": state})
        callback = parse_authorize_callback_response(f"{CALLBACK_URI}?{params}")
        assert callback.issuer is None

        # Strict opt-in: iss is required regardless of advertised metadata.
        required_result = validate_authorize_callback_issuer(
            callback, issuer, require=True
        )
        assert required_result.is_valid is False
        assert (
            required_result.result is AuthorizeCallbackValidationResult.MISSING_ISSUER
        )
        assert required_result.error == "missing_issuer"

        # Metadata-driven: node-oidc-provider advertises iss support, so an
        # absent iss driven from the live flag is likewise a failure. Assert
        # the advertised path against the real metadata value.
        advertised = bool(
            discovery_document.authorization_response_iss_parameter_supported
        )
        metadata_result = validate_authorize_callback_issuer(
            callback, issuer, iss_parameter_supported=advertised
        )
        if advertised:
            assert metadata_result.is_valid is False
            assert (
                metadata_result.result
                is AuthorizeCallbackValidationResult.MISSING_ISSUER
            )
        else:
            # AS does not advertise iss and it is not required -> nothing to
            # validate; an absent iss passes (no downgrade surprise).
            assert metadata_result.is_valid is True
            assert metadata_result.result is AuthorizeCallbackValidationResult.SUCCESS


@pytest.mark.integration
class TestLiveAuthorizeCallback:
    """Test callback validation with live auth code flow results.

    These tests use auth_code_result which skips when the provider
    does not support devInteractions.
    """

    def test_live_state_validation(self, auth_code_result):
        """Verify state parameter roundtrip from live flow."""
        assert auth_code_result["state_result"].is_valid is True
        assert auth_code_result["callback"].state == auth_code_result["state"]

    def test_live_state_mismatch(self, auth_code_result):
        """Wrong state returns STATE_MISMATCH against live callback."""
        callback = auth_code_result["callback"]
        wrong_state = "completely-wrong-state-value"
        state_result = validate_authorize_callback_state(callback, wrong_state)
        assert not state_result.is_valid
        assert state_result.result == AuthorizeCallbackValidationResult.STATE_MISMATCH

    def test_live_issuer_validation(self, auth_code_result, discovery_document):
        """RFC 9207: validate the live callback's iss against the expected issuer.

        When the AS emits ``iss`` (node-oidc-provider does), the validated path
        is exercised and must SUCCEED against the real issuer. When it does not,
        an absent-and-not-required iss also SUCCEEDS.
        """
        callback = auth_code_result["callback"]
        result = validate_authorize_callback_issuer(
            callback,
            discovery_document.issuer,
            iss_parameter_supported=bool(
                discovery_document.authorization_response_iss_parameter_supported
            ),
        )

        assert result.is_valid is True
        assert result.result is AuthorizeCallbackValidationResult.SUCCESS

    def test_live_issuer_mismatch_detected(self, auth_code_result):
        """A wrong expected issuer is rejected against the live callback's iss."""
        callback = auth_code_result["callback"]
        if not callback.issuer:
            pytest.skip("Provider did not return iss in the authorization response")

        result = validate_authorize_callback_issuer(
            callback, "https://attacker.example.com"
        )

        assert result.is_valid is False
        assert result.result is AuthorizeCallbackValidationResult.ISSUER_MISMATCH
