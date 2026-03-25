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
