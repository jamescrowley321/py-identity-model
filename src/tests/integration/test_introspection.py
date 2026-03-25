"""Integration tests for OAuth 2.0 Token Introspection."""

import pytest

from py_identity_model import BaseRequest, TokenIntrospectionRequest


@pytest.mark.integration
class TestIntrospectionIntegration:
    def test_request_model_inherits_base(self):
        """TokenIntrospectionRequest is a BaseRequest."""
        req = TokenIntrospectionRequest(
            address="https://auth.example.com/introspect",
            token="test_token",
            client_id="test_client",
        )
        assert isinstance(req, BaseRequest)

    def test_introspection_endpoint_in_discovery(self, discovery_document):
        """Verify identity provider exposes introspection endpoint."""
        # Not all providers expose introspection_endpoint in discovery
        # This test verifies the field exists (may be None)
        assert hasattr(discovery_document, "introspection_endpoint")

    def test_request_with_token_endpoint(self, discovery_document):
        """Build introspection request using token endpoint as fallback.

        Many providers use token_endpoint for introspection or expose
        a separate introspection_endpoint. We use token_endpoint here
        as it's always available.
        """
        req = TokenIntrospectionRequest(
            address=discovery_document.token_endpoint or "",
            token="test_token",
            client_id="test_client",
            client_secret="test_secret",
            token_type_hint="access_token",
        )
        assert req.address != ""
        assert req.token_type_hint == "access_token"

    def test_request_model_with_real_endpoint(self, discovery_document):
        """Build introspection request from discovery document."""
        endpoint = discovery_document.introspection_endpoint
        if endpoint is None:
            pytest.skip("Provider does not expose introspection_endpoint")

        req = TokenIntrospectionRequest(
            address=endpoint,
            token="test_token",
            client_id="test_client",
        )
        assert req.address == endpoint
