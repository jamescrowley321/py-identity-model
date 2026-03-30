"""Integration tests for authorization code grant with PKCE."""

import secrets

import pytest

from py_identity_model import (
    BaseRequest,
    build_authorization_url,
    generate_code_challenge,
    generate_pkce_pair,
    parse_authorize_callback_response,
    validate_authorize_callback_state,
)
from py_identity_model.core.models import AuthorizationCodeTokenRequest


@pytest.mark.integration
class TestAuthCodePKCEIntegration:
    def test_pkce_pair_round_trip(self):
        """Generate PKCE pair and verify challenge matches verifier."""
        verifier, challenge = generate_pkce_pair()
        assert challenge == generate_code_challenge(verifier)

    def test_build_authorize_url_from_discovery(self, discovery_document):
        """Build authorize URL using real discovery document metadata."""
        _verifier, challenge = generate_pkce_pair()
        state = secrets.token_urlsafe(32)

        url = build_authorization_url(
            authorization_endpoint=discovery_document.authorization_endpoint,
            client_id="test-client",
            redirect_uri="https://app.example.com/callback",
            scope="openid profile",
            state=state,
            code_challenge=challenge,
            code_challenge_method="S256",
        )

        assert discovery_document.authorization_endpoint in url
        assert "code_challenge=" in url
        assert "code_challenge_method=S256" in url
        assert f"state={state}" in url

    def test_full_flow_simulation(self, discovery_document):
        """Simulate the complete auth code + PKCE flow (except actual auth)."""
        # Step 1: Generate PKCE pair
        verifier, challenge = generate_pkce_pair()
        state = secrets.token_urlsafe(32)

        # Step 2: Build authorize URL
        url = build_authorization_url(
            authorization_endpoint=discovery_document.authorization_endpoint,
            client_id="test-client",
            redirect_uri="https://app.example.com/callback",
            state=state,
            code_challenge=challenge,
            code_challenge_method="S256",
        )
        # Verify the URL uses the scheme reported by the discovery document
        assert url.startswith(discovery_document.authorization_endpoint)

        # Step 3: Simulate callback (would come from browser redirect)
        callback = f"https://app.example.com/callback?code=simulated_code&state={state}"
        response = parse_authorize_callback_response(callback)
        assert response.is_successful
        assert response.code == "simulated_code"

        # Step 4: Validate state
        result = validate_authorize_callback_state(response, state)
        assert result.is_valid

        # Step 5: Build token exchange request
        token_request = AuthorizationCodeTokenRequest(
            address=discovery_document.token_endpoint or "",
            client_id="test-client",
            code=response.code,
            redirect_uri="https://app.example.com/callback",
            code_verifier=verifier,
        )
        assert isinstance(token_request, BaseRequest)
        assert token_request.code_verifier == verifier
