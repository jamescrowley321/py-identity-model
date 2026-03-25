"""Integration tests for OAuth 2.0 Refresh Token Grant."""

import pytest

from py_identity_model import BaseRequest, RefreshTokenRequest


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
