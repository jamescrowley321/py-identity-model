"""Integration tests for OAuth 2.0 Token Revocation."""

import pytest

from py_identity_model import BaseRequest, TokenRevocationRequest


@pytest.mark.integration
class TestRevocationIntegration:
    def test_request_model_inherits_base(self):
        req = TokenRevocationRequest(
            address="https://auth.example.com/revoke",
            token="test_token",
            client_id="test_client",
        )
        assert isinstance(req, BaseRequest)

    def test_request_with_token_endpoint(self, discovery_document):
        """Build revocation request using token endpoint as fallback."""
        req = TokenRevocationRequest(
            address=discovery_document.token_endpoint or "",
            token="test_token",
            client_id="test_client",
            client_secret="test_secret",
            token_type_hint="access_token",
        )
        assert req.address != ""
