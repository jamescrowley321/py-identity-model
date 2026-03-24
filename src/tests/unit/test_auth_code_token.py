"""Unit tests for authorization code token exchange."""

import httpx
import pytest
import respx

from py_identity_model.core.models import (
    AuthorizationCodeTokenRequest,
    AuthorizationCodeTokenResponse,
)
from py_identity_model.sync.token_client import (
    request_authorization_code_token,
)


TOKEN_URL = "https://auth.example.com/token"
TOKEN_JSON = {
    "access_token": "access_tok",
    "token_type": "Bearer",
    "expires_in": 3600,
    "refresh_token": "refresh_tok",
    "id_token": "id_tok",
}


@pytest.mark.unit
class TestAuthCodeTokenExchange:
    @respx.mock
    def test_success_with_pkce(self):
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=TOKEN_JSON)
        )

        request = AuthorizationCodeTokenRequest(
            address=TOKEN_URL,
            client_id="app1",
            code="auth_code_123",
            redirect_uri="https://app.com/cb",
            code_verifier="verifier_string",
        )
        response = request_authorization_code_token(request)

        assert response.is_successful is True
        assert response.token is not None
        assert response.token["access_token"] == "access_tok"
        assert response.token["refresh_token"] == "refresh_tok"

    @respx.mock
    def test_success_with_client_secret(self):
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=TOKEN_JSON)
        )

        request = AuthorizationCodeTokenRequest(
            address=TOKEN_URL,
            client_id="app1",
            code="auth_code_123",
            redirect_uri="https://app.com/cb",
            client_secret="secret",
        )
        response = request_authorization_code_token(request)

        assert response.is_successful is True

    @respx.mock
    def test_error_response(self):
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                400,
                json={"error": "invalid_grant"},
                content=b'{"error": "invalid_grant"}',
            )
        )

        request = AuthorizationCodeTokenRequest(
            address=TOKEN_URL,
            client_id="app1",
            code="expired_code",
            redirect_uri="https://app.com/cb",
        )
        response = request_authorization_code_token(request)

        assert response.is_successful is False

    def test_request_model_fields(self):
        req = AuthorizationCodeTokenRequest(
            address=TOKEN_URL,
            client_id="app1",
            code="code",
            redirect_uri="https://app.com/cb",
            code_verifier="verifier",
            client_secret="secret",
            scope="openid",
        )
        assert req.address == TOKEN_URL
        assert req.code_verifier == "verifier"
        assert req.client_secret == "secret"
        assert req.scope == "openid"

    def test_response_is_base_response(self):
        from py_identity_model import BaseResponse

        resp = AuthorizationCodeTokenResponse(is_successful=True, token={})
        assert isinstance(resp, BaseResponse)
