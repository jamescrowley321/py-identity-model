"""Integration tests for Pushed Authorization Requests (RFC 9126)."""

import pytest

from py_identity_model import BaseRequest, PushedAuthorizationRequest


@pytest.mark.integration
class TestPARIntegration:
    def test_request_model_inherits_base(self):
        req = PushedAuthorizationRequest(
            address="https://auth.example.com/par",
            client_id="app",
            redirect_uri="https://app.com/cb",
        )
        assert isinstance(req, BaseRequest)

    def test_request_with_all_params(self):
        req = PushedAuthorizationRequest(
            address="https://auth.example.com/par",
            client_id="app",
            redirect_uri="https://app.com/cb",
            scope="openid profile",
            state="csrf",
            nonce="nonce",
            code_challenge="challenge",
            code_challenge_method="S256",
            client_secret="secret",
        )
        assert req.scope == "openid profile"
        assert req.code_challenge_method == "S256"
