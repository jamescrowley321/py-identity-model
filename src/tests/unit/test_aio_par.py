"""Async tests for aio.par module (NFR-9 parity)."""

import httpx
import pytest
import respx

from py_identity_model import (
    BaseResponse,
    PushedAuthorizationRequest,
    PushedAuthorizationResponse,
)
from py_identity_model.aio.par import push_authorization_request


PAR_URL = "https://auth.example.com/par"
PAR_RESPONSE = {
    "request_uri": "urn:ietf:params:oauth:request_uri:abc123",
    "expires_in": 60,
}


@pytest.mark.asyncio
class TestAsyncPAR:
    @respx.mock
    async def test_successful_par(self):
        respx.post(PAR_URL).mock(
            return_value=httpx.Response(201, json=PAR_RESPONSE)
        )
        response = await push_authorization_request(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="app1",
                redirect_uri="https://app.com/cb",
                client_secret="secret",
            )
        )
        assert response.is_successful is True
        assert (
            response.request_uri == "urn:ietf:params:oauth:request_uri:abc123"
        )
        assert response.expires_in == 60

    @respx.mock
    async def test_par_with_pkce(self):
        respx.post(PAR_URL).mock(
            return_value=httpx.Response(201, json=PAR_RESPONSE)
        )
        response = await push_authorization_request(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="app1",
                redirect_uri="https://app.com/cb",
                code_challenge="challenge",
                code_challenge_method="S256",
            )
        )
        assert response.is_successful is True

    @respx.mock
    async def test_par_error(self):
        respx.post(PAR_URL).mock(
            return_value=httpx.Response(
                400, content=b'{"error":"invalid_request"}'
            )
        )
        response = await push_authorization_request(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="app1",
                redirect_uri="https://app.com/cb",
                client_secret="secret",
            )
        )
        assert response.is_successful is False

    @respx.mock
    async def test_confidential_client_uses_basic_auth_not_body(self):
        """M1: client_id must NOT appear in body when using Basic Auth."""
        route = respx.post(PAR_URL).mock(
            return_value=httpx.Response(201, json=PAR_RESPONSE)
        )
        await push_authorization_request(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="app1",
                redirect_uri="https://app.com/cb",
                client_secret="secret",
            )
        )
        request = route.calls[0].request
        assert request.headers.get("authorization") is not None
        assert request.headers["authorization"].startswith("Basic ")
        assert "client_id" not in request.content.decode()

    @respx.mock
    async def test_public_client_sends_client_id_in_body(self):
        """M1: public clients send client_id in POST body, no Basic Auth."""
        route = respx.post(PAR_URL).mock(
            return_value=httpx.Response(201, json=PAR_RESPONSE)
        )
        await push_authorization_request(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="public_app",
                redirect_uri="https://app.com/cb",
            )
        )
        request = route.calls[0].request
        body = request.content.decode()
        assert "client_id=public_app" in body
        assert request.headers.get("authorization") is None

    @respx.mock
    async def test_missing_request_uri_returns_error(self):
        """M2: Missing request_uri in successful response fails per RFC 9126 §2.2."""
        respx.post(PAR_URL).mock(
            return_value=httpx.Response(201, json={"expires_in": 60})
        )
        response = await push_authorization_request(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="app1",
                redirect_uri="https://app.com/cb",
                client_secret="secret",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "request_uri" in response.error

    @respx.mock
    async def test_missing_expires_in_returns_error(self):
        """M2: Missing expires_in in successful response fails per RFC 9126 §2.2."""
        respx.post(PAR_URL).mock(
            return_value=httpx.Response(
                201,
                json={
                    "request_uri": "urn:ietf:params:oauth:request_uri:abc123",
                },
            )
        )
        response = await push_authorization_request(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="app1",
                redirect_uri="https://app.com/cb",
                client_secret="secret",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "expires_in" in response.error

    async def test_pkce_requires_both_challenge_and_method(self):
        """S4: code_challenge and code_challenge_method must be paired."""
        with pytest.raises(ValueError, match="code_challenge"):
            await push_authorization_request(
                PushedAuthorizationRequest(
                    address=PAR_URL,
                    client_id="app1",
                    redirect_uri="https://app.com/cb",
                    code_challenge="challenge",
                )
            )

    @respx.mock
    async def test_network_error(self):
        respx.post(PAR_URL).mock(
            side_effect=httpx.ConnectError("Connection refused")
        )
        response = await push_authorization_request(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="app1",
                redirect_uri="https://app.com/cb",
                client_secret="secret",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "Connection refused" in response.error

    async def test_response_inherits_base(self):
        resp = PushedAuthorizationResponse(
            is_successful=True, request_uri="urn:...", expires_in=60
        )
        assert isinstance(resp, BaseResponse)

    @respx.mock
    async def test_content_type_header(self):
        """RFC 9126: PAR uses form-urlencoded content type."""
        route = respx.post(PAR_URL).mock(
            return_value=httpx.Response(201, json=PAR_RESPONSE)
        )
        await push_authorization_request(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="app1",
                redirect_uri="https://app.com/cb",
                client_secret="secret",
            )
        )
        request = route.calls[0].request
        assert (
            request.headers["content-type"]
            == "application/x-www-form-urlencoded"
        )
