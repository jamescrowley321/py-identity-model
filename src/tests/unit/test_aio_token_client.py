"""Async tests for aio.token_client module."""

import httpx
import pytest
import respx

from py_identity_model.aio.token_client import (
    ClientCredentialsTokenRequest,
    request_client_credentials_token,
)


@pytest.mark.asyncio
class TestAsyncTokenClient:
    @respx.mock
    async def test_async_request_client_credentials_token_success(self):
        """Test successful async client credentials token request"""
        url = "https://example.com/token"
        respx.post(url).mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": "test_token",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                },
            )
        )

        request = ClientCredentialsTokenRequest(
            address=url,
            client_id="test_client",
            client_secret="test_secret",
            scope="test_scope",
        )
        result = await request_client_credentials_token(request)

        assert result.is_successful is True
        assert result.token is not None
        assert result.token["access_token"] == "test_token"
        assert result.token["token_type"] == "Bearer"
        assert result.error is None

    @respx.mock
    async def test_async_request_client_credentials_token_http_error(self):
        """Test async client credentials token request with HTTP error"""
        url = "https://example.com/token"
        respx.post(url).mock(
            return_value=httpx.Response(401, content=b"Unauthorized")
        )

        request = ClientCredentialsTokenRequest(
            address=url,
            client_id="test_client",
            client_secret="wrong_secret",
            scope="test_scope",
        )
        result = await request_client_credentials_token(request)

        assert result.is_successful is False
        assert result.token is None
        assert result.error is not None
        assert "401" in result.error

    @respx.mock
    async def test_async_request_client_credentials_token_network_error(self):
        """Test async client credentials token request with network error"""
        url = "https://example.com/token"
        respx.post(url).mock(side_effect=httpx.ConnectError("Network error"))

        request = ClientCredentialsTokenRequest(
            address=url,
            client_id="test_client",
            client_secret="test_secret",
            scope="test_scope",
        )
        result = await request_client_credentials_token(request)

        assert result.is_successful is False
        assert result.error is not None
        assert "Network error" in result.error
