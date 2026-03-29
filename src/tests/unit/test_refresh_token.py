"""Unit tests for OAuth 2.0 Refresh Token Grant."""

import httpx
import pytest
import respx

from py_identity_model import (
    BaseRequest,
    BaseResponse,
    RefreshTokenRequest,
    RefreshTokenResponse,
)
from py_identity_model.exceptions import FailedResponseAccessError
from py_identity_model.sync.token_client import refresh_token


TOKEN_URL = "https://auth.example.com/token"
TOKEN_JSON = {
    "access_token": "new_access_token",
    "token_type": "Bearer",
    "expires_in": 3600,
    "refresh_token": "new_refresh_token",
}


@pytest.mark.unit
class TestRefreshToken:
    @respx.mock
    def test_successful_refresh(self):
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=TOKEN_JSON)
        )

        response = refresh_token(
            RefreshTokenRequest(
                address=TOKEN_URL,
                client_id="app1",
                refresh_token="old_refresh_token",
                client_secret="secret",
            )
        )

        assert response.is_successful is True
        assert response.token is not None
        assert response.token["access_token"] == "new_access_token"

    @respx.mock
    def test_refresh_with_scope(self):
        route = respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=TOKEN_JSON)
        )

        response = refresh_token(
            RefreshTokenRequest(
                address=TOKEN_URL,
                client_id="app1",
                refresh_token="rt",
                client_secret="secret",
                scope="openid profile",
            )
        )

        assert response.is_successful is True
        request = route.calls[0].request
        body = request.content.decode()
        assert "scope=openid" in body

    @respx.mock
    def test_expired_refresh_token(self):
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                400, content=b'{"error": "invalid_grant"}'
            )
        )

        response = refresh_token(
            RefreshTokenRequest(
                address=TOKEN_URL,
                client_id="app1",
                refresh_token="expired_rt",
                client_secret="secret",
            )
        )

        assert response.is_successful is False

    @respx.mock
    def test_public_client_refresh(self):
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=TOKEN_JSON)
        )

        response = refresh_token(
            RefreshTokenRequest(
                address=TOKEN_URL,
                client_id="public_app",
                refresh_token="rt",
            )
        )

        assert response.is_successful is True

    @respx.mock
    def test_failed_response_guard(self):
        """Accessing .token on failed response raises FailedResponseAccessError."""
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                401, content=b'{"error": "invalid_client"}'
            )
        )

        response = refresh_token(
            RefreshTokenRequest(
                address=TOKEN_URL,
                client_id="app1",
                refresh_token="rt",
                client_secret="wrong",
            )
        )

        assert response.is_successful is False
        with pytest.raises(FailedResponseAccessError):
            _ = response.token

    @respx.mock
    def test_network_error(self):
        """Network errors are caught and returned as error responses."""
        respx.post(TOKEN_URL).mock(
            side_effect=httpx.ConnectError("Connection refused")
        )

        response = refresh_token(
            RefreshTokenRequest(
                address=TOKEN_URL,
                client_id="app1",
                refresh_token="rt",
                client_secret="secret",
            )
        )

        assert response.is_successful is False
        assert response.error is not None
        assert "Connection refused" in response.error

    def test_request_inherits_base(self):
        req = RefreshTokenRequest(
            address=TOKEN_URL, client_id="app", refresh_token="rt"
        )
        assert isinstance(req, BaseRequest)

    def test_response_inherits_base(self):
        resp = RefreshTokenResponse(is_successful=True, token={})
        assert isinstance(resp, BaseResponse)
