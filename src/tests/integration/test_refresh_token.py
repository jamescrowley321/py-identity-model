"""Integration tests for OAuth 2.0 Refresh Token Grant."""

import pytest

from py_identity_model import BaseRequest, RefreshTokenRequest
from py_identity_model.sync.token_client import refresh_token


@pytest.mark.integration
class TestRefreshTokenIntegration:
    def test_request_model_inherits_base(self):
        req = RefreshTokenRequest(
            address="https://auth.example.com/token",
            client_id="app",
            refresh_token="rt",
        )
        assert isinstance(req, BaseRequest)

    def test_request_with_real_token_endpoint(self, discovery_document):
        req = RefreshTokenRequest(
            address=discovery_document.token_endpoint or "",
            client_id="test_client",
            refresh_token="test_refresh_token",
            client_secret="test_secret",
        )
        assert req.address != ""

    def test_invalid_refresh_token_returns_error(
        self, discovery_document, test_config
    ):
        """Sending an invalid refresh token to the real endpoint returns an error."""
        response = refresh_token(
            RefreshTokenRequest(
                address=discovery_document.token_endpoint or "",
                client_id=test_config["TEST_CLIENT_ID"],
                refresh_token="invalid_refresh_token",
                client_secret=test_config.get("TEST_CLIENT_SECRET", ""),
            )
        )
        assert response.is_successful is False
        assert response.error is not None
