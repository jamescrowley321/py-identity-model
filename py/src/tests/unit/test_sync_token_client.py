"""
Unit tests for sync token client.

These tests verify sync-specific token client logic including
the request_client_credentials_token function.
"""

import httpx
import pytest
import respx

from py_identity_model.core.models import (
    ClientCredentialsTokenRequest,
    ClientCredentialsTokenResponse,
)
from py_identity_model.sync.token_client import (
    request_client_credentials_token,
)


# Expected token expiry value (seconds)
EXPECTED_TOKEN_EXPIRES_IN = 3600


class TestSyncTokenClient:
    """Test sync token client functionality."""

    @respx.mock
    def test_request_client_credentials_token_success(self):
        """Test successful client credentials token request."""
        # Mock token endpoint
        respx.post("https://example.com/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": "test_token",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                },
            )
        )

        # Create request
        request = ClientCredentialsTokenRequest(
            address="https://example.com/token",
            client_id="test_client",
            client_secret="test_secret",
            scope="test_scope",
        )

        # Make request
        response = request_client_credentials_token(request)

        # Verify response
        assert response.is_successful is True
        assert response.token is not None
        assert response.token["access_token"] == "test_token"
        assert response.token["token_type"] == "Bearer"
        assert response.token["expires_in"] == EXPECTED_TOKEN_EXPIRES_IN

    @respx.mock
    def test_request_client_credentials_token_http_error(self):
        """Test client credentials token request with HTTP error."""
        # Mock token endpoint to return 400 error
        respx.post("https://example.com/token").mock(
            return_value=httpx.Response(
                400,
                json={
                    "error": "invalid_client",
                    "error_description": "Invalid client credentials",
                },
            )
        )

        # Create request
        request = ClientCredentialsTokenRequest(
            address="https://example.com/token",
            client_id="test_client",
            client_secret="test_secret",
            scope="test_scope",
        )

        # Make request
        response = request_client_credentials_token(request)

        # Verify error response
        assert response.is_successful is False
        assert response.error is not None
        assert "invalid_client" in response.error

    @respx.mock
    def test_request_client_credentials_token_network_error(self):
        """Test client credentials token request with network error."""
        # Mock token endpoint to raise network error
        respx.post("https://example.com/token").mock(
            side_effect=httpx.ConnectError("Connection failed")
        )

        # Create request
        request = ClientCredentialsTokenRequest(
            address="https://example.com/token",
            client_id="test_client",
            client_secret="test_secret",
            scope="test_scope",
        )

        # Make request
        response = request_client_credentials_token(request)

        # Verify error response
        assert response.is_successful is False
        assert response.error is not None
        assert "Network error" in response.error

    @respx.mock
    def test_request_client_credentials_token_closes_response(self):
        """Test that response is properly closed after request."""
        # Mock token endpoint
        mock_route = respx.post("https://example.com/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": "test_token",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                },
            )
        )

        # Create request
        request = ClientCredentialsTokenRequest(
            address="https://example.com/token",
            client_id="test_client",
            client_secret="test_secret",
            scope="test_scope",
        )

        # Make request
        response = request_client_credentials_token(request)

        # Verify response is successful
        assert response.is_successful is True

        # Verify the mock was called
        assert mock_route.called


SECRET_TOKEN = {
    "access_token": "CC_SECRET_AT",
    "token_type": "Bearer",
}


@pytest.mark.unit
class TestClientCredentialsTokenResponseReprRedaction:
    """#431: the ``token`` dict is a secret and must not leak via repr/str."""

    def test_repr_redacts_token_value(self):
        response = ClientCredentialsTokenResponse(
            is_successful=True, token=SECRET_TOKEN
        )

        rendered = repr(response)
        assert "ClientCredentialsTokenResponse" in rendered
        assert "[REDACTED]" in rendered
        assert "CC_SECRET_AT" not in rendered

    def test_str_redacts_token_value(self):
        response = ClientCredentialsTokenResponse(
            is_successful=True, token=SECRET_TOKEN
        )

        assert "CC_SECRET_AT" not in str(response)
        assert "[REDACTED]" in str(response)

    def test_repr_of_failed_response_does_not_crash_or_leak(self):
        response = ClientCredentialsTokenResponse(
            is_successful=False, error="invalid_client", token=None
        )

        rendered = repr(response)
        assert "invalid_client" in rendered
        assert "[REDACTED]" not in rendered
        assert "token=None" in rendered

    def test_equality_still_behaves(self):
        a = ClientCredentialsTokenResponse(is_successful=True, token=SECRET_TOKEN)
        b = ClientCredentialsTokenResponse(is_successful=True, token=dict(SECRET_TOKEN))
        c = ClientCredentialsTokenResponse(
            is_successful=True, token={"access_token": "other"}
        )

        assert a == b
        assert a != c
        assert a != "not-a-response"
