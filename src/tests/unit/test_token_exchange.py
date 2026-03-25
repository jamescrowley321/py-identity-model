"""Unit tests for Token Exchange (RFC 8693)."""

import httpx
import pytest
import respx

from py_identity_model import (
    BaseRequest,
    BaseResponse,
    TokenExchangeRequest,
    TokenExchangeResponse,
)
from py_identity_model.core.token_type import ACCESS_TOKEN, ID_TOKEN, JWT
from py_identity_model.sync.token_exchange import exchange_token


TOKEN_URL = "https://auth.example.com/token"

TOKEN_EXCHANGE_RESPONSE = {
    "access_token": "eyJhbGci...",
    "issued_token_type": ACCESS_TOKEN,
    "token_type": "Bearer",
    "expires_in": 3600,
}


@pytest.mark.unit
class TestExchangeToken:
    @respx.mock
    def test_successful_impersonation(self):
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=TOKEN_EXCHANGE_RESPONSE)
        )
        response = exchange_token(
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
    def test_successful_delegation(self):
        delegation_response = {
            **TOKEN_EXCHANGE_RESPONSE,
            "issued_token_type": ACCESS_TOKEN,
        }
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=delegation_response)
        )
        response = exchange_token(
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
    def test_with_all_optional_params(self):
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=TOKEN_EXCHANGE_RESPONSE)
        )
        response = exchange_token(
            TokenExchangeRequest(
                address=TOKEN_URL,
                client_id="service-a",
                subject_token="user-token",
                subject_token_type=ACCESS_TOKEN,
                resource="https://api.example.com",
                audience="api-service",
                scope="read write",
                requested_token_type=ID_TOKEN,
                client_secret="secret",
            )
        )
        assert response.is_successful is True

    @respx.mock
    def test_error_response(self):
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                400,
                content=b'{"error":"invalid_grant","error_description":"Subject token expired"}',
            )
        )
        response = exchange_token(
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
    def test_public_client(self):
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=TOKEN_EXCHANGE_RESPONSE)
        )
        response = exchange_token(
            TokenExchangeRequest(
                address=TOKEN_URL,
                client_id="public-app",
                subject_token="user-token",
                subject_token_type=ACCESS_TOKEN,
            )
        )
        assert response.is_successful is True

    def test_request_inherits_base(self):
        req = TokenExchangeRequest(
            address=TOKEN_URL,
            client_id="app",
            subject_token="tok",
            subject_token_type=ACCESS_TOKEN,
        )
        assert isinstance(req, BaseRequest)

    def test_response_inherits_base(self):
        resp = TokenExchangeResponse(
            is_successful=True,
            token={"access_token": "tok"},
            issued_token_type=ACCESS_TOKEN,
        )
        assert isinstance(resp, BaseResponse)
