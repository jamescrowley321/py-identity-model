"""Unit tests for HTTP Basic client-auth credential encoding (RFC 6749 §2.3.1)."""

import base64

import httpx
import pytest
import respx

from py_identity_model.core.client_auth import basic_auth_credentials
from py_identity_model.core.models import AuthorizationCodeTokenRequest
from py_identity_model.sync.token_client import request_authorization_code_token


TOKEN_URL = "https://auth.example.com/token"
TOKEN_JSON = {"access_token": "a", "token_type": "Bearer", "expires_in": 3600}


@pytest.mark.unit
class TestBasicAuthCredentials:
    def test_plain_credentials_pass_through(self):
        # Clean ASCII credentials are unchanged — a no-op for the common case.
        assert basic_auth_credentials("app1", "secret") == ("app1", "secret")

    def test_reserved_characters_are_percent_encoded(self):
        # +, /, %, ':' and space must all be escaped so an authorization server
        # that form-urldecodes per RFC 6749 §2.3.1 recovers the exact values.
        client_id, client_secret = basic_auth_credentials("cli:ent", "a+b/c%d e")
        assert client_id == "cli%3Aent"
        assert client_secret == "a%2Bb%2Fc%25d%20e"

    @respx.mock
    def test_auth_header_encodes_special_secret_end_to_end(self):
        # A dynamically-issued secret with reserved characters must reach the
        # token endpoint form-urlencoded inside the Basic header, not verbatim.
        route = respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=TOKEN_JSON)
        )
        request = AuthorizationCodeTokenRequest(
            address=TOKEN_URL,
            client_id="app1",
            code="auth_code_123",
            redirect_uri="https://app.com/cb",
            client_secret="a+b/c%d",
        )
        request_authorization_code_token(request)

        header = route.calls[0].request.headers["Authorization"]
        assert header.startswith("Basic ")
        decoded = base64.b64decode(header[len("Basic ") :]).decode()
        assert decoded == "app1:a%2Bb%2Fc%25d"
