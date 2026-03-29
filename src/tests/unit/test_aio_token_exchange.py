"""Async tests for aio.token_exchange module (NFR-9 parity)."""

import httpx
import pytest
import respx

from py_identity_model import (
    BaseRequest,
    BaseResponse,
    TokenExchangeRequest,
    TokenExchangeResponse,
)
from py_identity_model.aio.token_exchange import exchange_token
from py_identity_model.core.token_type import ACCESS_TOKEN, JWT


TOKEN_URL = "https://auth.example.com/token"

TOKEN_EXCHANGE_RESPONSE = {
    "access_token": "eyJhbGci...",
    "issued_token_type": ACCESS_TOKEN,
    "token_type": "Bearer",
    "expires_in": 3600,
}


@pytest.mark.asyncio
class TestAsyncExchangeToken:
    @respx.mock
    async def test_successful_impersonation(self):
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=TOKEN_EXCHANGE_RESPONSE)
        )
        response = await exchange_token(
            TokenExchangeRequest(
                address=TOKEN_URL,
                client_id="service-a",
                subject_token="user-access-token",
                subject_token_type=ACCESS_TOKEN,
                client_secret="secret",
            )
        )
        assert response.is_successful is True
        assert response.token is not None
        assert response.token["access_token"] == "eyJhbGci..."
        assert response.issued_token_type == ACCESS_TOKEN

    @respx.mock
    async def test_successful_delegation(self):
        delegation_response = {
            **TOKEN_EXCHANGE_RESPONSE,
            "issued_token_type": ACCESS_TOKEN,
        }
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=delegation_response)
        )
        response = await exchange_token(
            TokenExchangeRequest(
                address=TOKEN_URL,
                client_id="service-a",
                subject_token="user-access-token",
                subject_token_type=ACCESS_TOKEN,
                actor_token="service-a-token",
                actor_token_type=JWT,
                client_secret="secret",
            )
        )
        assert response.is_successful is True
        assert response.token is not None

    @respx.mock
    async def test_with_all_optional_params(self):
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=TOKEN_EXCHANGE_RESPONSE)
        )
        response = await exchange_token(
            TokenExchangeRequest(
                address=TOKEN_URL,
                client_id="service-a",
                subject_token="user-token",
                subject_token_type=ACCESS_TOKEN,
                resource="https://api.example.com",
                audience="api-service",
                scope="read write",
                requested_token_type=ACCESS_TOKEN,
                client_secret="secret",
            )
        )
        assert response.is_successful is True

    @respx.mock
    async def test_error_response(self):
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                400,
                content=b'{"error":"invalid_grant","error_description":"Subject token expired"}',
            )
        )
        response = await exchange_token(
            TokenExchangeRequest(
                address=TOKEN_URL,
                client_id="service-a",
                subject_token="expired-token",
                subject_token_type=ACCESS_TOKEN,
                client_secret="secret",
            )
        )
        assert response.is_successful is False

    @respx.mock
    async def test_public_client(self):
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=TOKEN_EXCHANGE_RESPONSE)
        )
        response = await exchange_token(
            TokenExchangeRequest(
                address=TOKEN_URL,
                client_id="public-app",
                subject_token="user-token",
                subject_token_type=ACCESS_TOKEN,
            )
        )
        assert response.is_successful is True

    @respx.mock
    async def test_public_client_sends_client_id_in_body(self):
        """M1: Public clients send client_id in form body."""
        route = respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=TOKEN_EXCHANGE_RESPONSE)
        )
        await exchange_token(
            TokenExchangeRequest(
                address=TOKEN_URL,
                client_id="public-app",
                subject_token="user-token",
                subject_token_type=ACCESS_TOKEN,
            )
        )
        request = route.calls[0].request
        body = request.content.decode()
        assert "client_id=public-app" in body

    @respx.mock
    async def test_confidential_client_excludes_client_id_from_body(self):
        """M1: Confidential clients use Basic Auth, no client_id in body."""
        route = respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=TOKEN_EXCHANGE_RESPONSE)
        )
        await exchange_token(
            TokenExchangeRequest(
                address=TOKEN_URL,
                client_id="service-a",
                subject_token="user-token",
                subject_token_type=ACCESS_TOKEN,
                client_secret="secret",
            )
        )
        request = route.calls[0].request
        body = request.content.decode()
        assert "client_id=" not in body
        assert request.headers.get("authorization") is not None

    async def test_actor_token_without_type_returns_error(self):
        """M2: actor_token without actor_token_type returns error response."""
        response = await exchange_token(
            TokenExchangeRequest(
                address=TOKEN_URL,
                client_id="service-a",
                subject_token="user-token",
                subject_token_type=ACCESS_TOKEN,
                actor_token="actor-token",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "actor_token_type is REQUIRED" in response.error

    async def test_empty_subject_token_returns_error(self):
        """S2: Empty subject_token returns error response."""
        response = await exchange_token(
            TokenExchangeRequest(
                address=TOKEN_URL,
                client_id="service-a",
                subject_token="",
                subject_token_type=ACCESS_TOKEN,
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "subject_token must not be empty" in response.error

    async def test_empty_actor_token_returns_error(self):
        """S2: Empty actor_token returns error response."""
        response = await exchange_token(
            TokenExchangeRequest(
                address=TOKEN_URL,
                client_id="service-a",
                subject_token="user-token",
                subject_token_type=ACCESS_TOKEN,
                actor_token="",
                actor_token_type=JWT,
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "actor_token must not be empty" in response.error

    @respx.mock
    async def test_non_json_success_returns_error(self):
        """S3: Non-JSON body on 200 returns error instead of crashing."""
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                200, content=b"<html>Gateway Error</html>"
            )
        )
        response = await exchange_token(
            TokenExchangeRequest(
                address=TOKEN_URL,
                client_id="service-a",
                subject_token="user-token",
                subject_token_type=ACCESS_TOKEN,
                client_secret="secret",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "invalid JSON" in response.error

    @respx.mock
    async def test_non_dict_json_success_returns_error(self):
        """S3: Non-dict JSON on 200 returns error instead of AttributeError."""
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=["not", "a", "dict"])
        )
        response = await exchange_token(
            TokenExchangeRequest(
                address=TOKEN_URL,
                client_id="service-a",
                subject_token="user-token",
                subject_token_type=ACCESS_TOKEN,
                client_secret="secret",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "not a JSON object" in response.error

    @respx.mock
    async def test_network_error(self):
        respx.post(TOKEN_URL).mock(
            side_effect=httpx.ConnectError("Connection refused")
        )
        response = await exchange_token(
            TokenExchangeRequest(
                address=TOKEN_URL,
                client_id="service-a",
                subject_token="user-token",
                subject_token_type=ACCESS_TOKEN,
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "Connection refused" in response.error

    async def test_request_inherits_base(self):
        req = TokenExchangeRequest(
            address=TOKEN_URL,
            client_id="app",
            subject_token="tok",
            subject_token_type=ACCESS_TOKEN,
        )
        assert isinstance(req, BaseRequest)

    async def test_response_inherits_base(self):
        resp = TokenExchangeResponse(
            is_successful=True,
            token={"access_token": "tok"},
            issued_token_type=ACCESS_TOKEN,
        )
        assert isinstance(resp, BaseResponse)
