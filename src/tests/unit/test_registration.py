"""Unit tests for Dynamic Client Registration (RFC 7591).

Covers spec IDs:
- DYN-001: register with minimal metadata (redirect_uris only)
- DYN-002: register with full metadata
- DYN-004: invalid_redirect_uri error
- DYN-005: invalid_client_metadata error
"""

import httpx
import pytest
import respx

import py_identity_model
from py_identity_model import (
    BaseRequest,
    BaseResponse,
    ClientRegistrationRequest,
    ClientRegistrationResponse,
    register_client,
)
import py_identity_model.aio as pim_aio
from py_identity_model.aio.registration import register_client as async_register_client


REGISTRATION_URL = "https://auth.example.com/register"

# Expected timestamps echoed by the mocked registration responses.
EXPECTED_CLIENT_ID_ISSUED_AT = 2893256800
EXPECTED_CLIENT_SECRET_EXPIRES_AT = 2893276800

MINIMAL_RESPONSE = {
    "client_id": "s6BhdRkqt3",
    "client_id_issued_at": 2893256800,
    "registration_access_token": "reg-23410913-abewfq.123483",
    "registration_client_uri": "https://auth.example.com/register/s6BhdRkqt3",
    "redirect_uris": ["https://app.example.com/cb"],
}

FULL_RESPONSE = {
    "client_id": "s6BhdRkqt3",
    "client_secret": "cf136dc3c1fc93f31185e5885805d",
    "client_id_issued_at": 2893256800,
    "client_secret_expires_at": 2893276800,
    "registration_access_token": "reg-23410913-abewfq.123483",
    "registration_client_uri": "https://auth.example.com/register/s6BhdRkqt3",
    "redirect_uris": ["https://app.example.com/cb"],
    "client_name": "Example Client",
    "grant_types": ["authorization_code", "refresh_token"],
    "token_endpoint_auth_method": "client_secret_basic",
    "scope": "openid profile email",
    "subject_type": "public",
}


@pytest.mark.unit
class TestRegisterClient:
    @respx.mock
    def test_register_minimal_metadata(self):
        # DYN-001: minimal registration returns issued client_id + mgmt fields.
        respx.post(REGISTRATION_URL).mock(
            return_value=httpx.Response(201, json=MINIMAL_RESPONSE)
        )
        response = register_client(
            ClientRegistrationRequest(
                address=REGISTRATION_URL,
                redirect_uris=["https://app.example.com/cb"],
            )
        )
        assert response.is_successful is True
        assert response.client_id == "s6BhdRkqt3"
        assert response.client_id_issued_at == EXPECTED_CLIENT_ID_ISSUED_AT
        assert response.registration_access_token == "reg-23410913-abewfq.123483"
        assert response.registration_client_uri is not None
        assert response.registration_client_uri.endswith("/s6BhdRkqt3")

    @respx.mock
    def test_register_minimal_sends_only_redirect_uris(self):
        # DYN-001: minimal request body carries redirect_uris and nothing unset.
        route = respx.post(REGISTRATION_URL).mock(
            return_value=httpx.Response(201, json=MINIMAL_RESPONSE)
        )
        register_client(
            ClientRegistrationRequest(
                address=REGISTRATION_URL,
                redirect_uris=["https://app.example.com/cb"],
            )
        )
        request = route.calls[0].request
        assert request.headers["content-type"] == "application/json"
        body = request.content.decode()
        assert "redirect_uris" in body
        assert "client_name" not in body

    @respx.mock
    def test_register_full_metadata(self):
        # DYN-002: full metadata registration echoes secret + metadata.
        route = respx.post(REGISTRATION_URL).mock(
            return_value=httpx.Response(201, json=FULL_RESPONSE)
        )
        response = register_client(
            ClientRegistrationRequest(
                address=REGISTRATION_URL,
                redirect_uris=["https://app.example.com/cb"],
                client_name="Example Client",
                grant_types=["authorization_code", "refresh_token"],
                token_endpoint_auth_method="client_secret_basic",
                scope="openid profile email",
                extra_metadata={"subject_type": "public"},
            )
        )
        assert response.is_successful is True
        assert response.client_secret == "cf136dc3c1fc93f31185e5885805d"
        assert response.client_secret_expires_at == EXPECTED_CLIENT_SECRET_EXPIRES_AT
        assert response.metadata is not None
        assert response.metadata["client_name"] == "Example Client"
        assert response.metadata["subject_type"] == "public"
        # extra_metadata passes through into the request body.
        sent = route.calls[0].request.content.decode()
        assert "subject_type" in sent
        assert "client_name" in sent

    @respx.mock
    def test_register_accepts_200_status(self):
        # RFC 7591 §3.2.1 specifies 201, but accept any 2xx.
        respx.post(REGISTRATION_URL).mock(
            return_value=httpx.Response(200, json=MINIMAL_RESPONSE)
        )
        response = register_client(
            ClientRegistrationRequest(
                address=REGISTRATION_URL,
                redirect_uris=["https://app.example.com/cb"],
            )
        )
        assert response.is_successful is True
        assert response.client_id == "s6BhdRkqt3"

    @respx.mock
    def test_register_with_initial_access_token(self):
        # Protected registration endpoint carries a Bearer initial access token.
        route = respx.post(REGISTRATION_URL).mock(
            return_value=httpx.Response(201, json=MINIMAL_RESPONSE)
        )
        register_client(
            ClientRegistrationRequest(
                address=REGISTRATION_URL,
                redirect_uris=["https://app.example.com/cb"],
                initial_access_token="init-token-123",
            )
        )
        request = route.calls[0].request
        assert request.headers["authorization"] == "Bearer init-token-123"

    @respx.mock
    def test_register_invalid_redirect_uri(self):
        # DYN-004: invalid_redirect_uri surfaces the error code.
        respx.post(REGISTRATION_URL).mock(
            return_value=httpx.Response(
                400,
                json={
                    "error": "invalid_redirect_uri",
                    "error_description": "redirect_uri is not https",
                },
            )
        )
        response = register_client(
            ClientRegistrationRequest(
                address=REGISTRATION_URL,
                redirect_uris=["http://insecure.example.com/cb"],
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "invalid_redirect_uri" in response.error
        assert "redirect_uri is not https" in response.error

    @respx.mock
    def test_register_invalid_client_metadata(self):
        # DYN-005: invalid_client_metadata surfaces the error code.
        respx.post(REGISTRATION_URL).mock(
            return_value=httpx.Response(
                400,
                json={
                    "error": "invalid_client_metadata",
                    "error_description": "grant_types unsupported",
                },
            )
        )
        response = register_client(
            ClientRegistrationRequest(
                address=REGISTRATION_URL,
                redirect_uris=["https://app.example.com/cb"],
                grant_types=["urn:example:unsupported"],
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "invalid_client_metadata" in response.error

    @respx.mock
    def test_register_error_without_json_body(self):
        # Non-JSON error body falls back to status + text.
        respx.post(REGISTRATION_URL).mock(
            return_value=httpx.Response(500, content=b"<html>boom</html>")
        )
        response = register_client(
            ClientRegistrationRequest(
                address=REGISTRATION_URL,
                redirect_uris=["https://app.example.com/cb"],
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "500" in response.error

    @respx.mock
    def test_register_success_missing_client_id(self):
        # A 2xx body without client_id is treated as an error (RFC 7591 §3.2.1).
        respx.post(REGISTRATION_URL).mock(
            return_value=httpx.Response(201, json={"redirect_uris": ["x"]})
        )
        response = register_client(
            ClientRegistrationRequest(
                address=REGISTRATION_URL,
                redirect_uris=["https://app.example.com/cb"],
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "client_id" in response.error

    @respx.mock
    def test_register_non_json_success(self):
        respx.post(REGISTRATION_URL).mock(
            return_value=httpx.Response(
                201, content=b"OK", headers={"content-type": "text/plain"}
            )
        )
        response = register_client(
            ClientRegistrationRequest(
                address=REGISTRATION_URL,
                redirect_uris=["https://app.example.com/cb"],
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "invalid JSON" in response.error

    @respx.mock
    def test_register_network_error(self):
        respx.post(REGISTRATION_URL).mock(
            side_effect=httpx.ConnectError("Connection refused")
        )
        response = register_client(
            ClientRegistrationRequest(
                address=REGISTRATION_URL,
                redirect_uris=["https://app.example.com/cb"],
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "Connection refused" in response.error


@pytest.mark.unit
class TestRegistrationModels:
    def test_request_inherits_base_request(self):
        req = ClientRegistrationRequest(
            address=REGISTRATION_URL, redirect_uris=["https://app.example.com/cb"]
        )
        assert isinstance(req, BaseRequest)

    def test_response_inherits_base_response(self):
        resp = ClientRegistrationResponse(is_successful=True, client_id="abc")
        assert isinstance(resp, BaseResponse)

    def test_guarded_fields_block_on_failure(self):
        resp = ClientRegistrationResponse(is_successful=False, error="nope")
        with pytest.raises(Exception, match="nope"):
            _ = resp.client_id

    def test_register_client_public_from_sync_and_aio(self):
        # Export-identity parity: register_client is public on both surfaces.
        assert "register_client" in py_identity_model.__all__
        assert "register_client" in pim_aio.__all__
        assert callable(py_identity_model.register_client)
        assert callable(pim_aio.register_client)


@pytest.mark.asyncio
class TestAsyncRegisterClient:
    @respx.mock
    async def test_register_minimal_metadata(self):
        # DYN-001 (async parity)
        respx.post(REGISTRATION_URL).mock(
            return_value=httpx.Response(201, json=MINIMAL_RESPONSE)
        )
        response = await async_register_client(
            ClientRegistrationRequest(
                address=REGISTRATION_URL,
                redirect_uris=["https://app.example.com/cb"],
            )
        )
        assert response.is_successful is True
        assert response.client_id == "s6BhdRkqt3"
        assert response.registration_access_token == "reg-23410913-abewfq.123483"

    @respx.mock
    async def test_register_full_metadata(self):
        # DYN-002 (async parity)
        respx.post(REGISTRATION_URL).mock(
            return_value=httpx.Response(201, json=FULL_RESPONSE)
        )
        response = await async_register_client(
            ClientRegistrationRequest(
                address=REGISTRATION_URL,
                redirect_uris=["https://app.example.com/cb"],
                client_name="Example Client",
                extra_metadata={"subject_type": "public"},
            )
        )
        assert response.is_successful is True
        assert response.client_secret == "cf136dc3c1fc93f31185e5885805d"
        assert response.metadata is not None
        assert response.metadata["subject_type"] == "public"

    @respx.mock
    async def test_register_invalid_redirect_uri(self):
        # DYN-004 (async parity)
        respx.post(REGISTRATION_URL).mock(
            return_value=httpx.Response(400, json={"error": "invalid_redirect_uri"})
        )
        response = await async_register_client(
            ClientRegistrationRequest(
                address=REGISTRATION_URL,
                redirect_uris=["http://insecure.example.com/cb"],
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "invalid_redirect_uri" in response.error

    @respx.mock
    async def test_register_invalid_client_metadata(self):
        # DYN-005 (async parity)
        respx.post(REGISTRATION_URL).mock(
            return_value=httpx.Response(400, json={"error": "invalid_client_metadata"})
        )
        response = await async_register_client(
            ClientRegistrationRequest(
                address=REGISTRATION_URL,
                redirect_uris=["https://app.example.com/cb"],
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "invalid_client_metadata" in response.error

    @respx.mock
    async def test_register_network_error(self):
        respx.post(REGISTRATION_URL).mock(
            side_effect=httpx.ConnectError("Connection refused")
        )
        response = await async_register_client(
            ClientRegistrationRequest(
                address=REGISTRATION_URL,
                redirect_uris=["https://app.example.com/cb"],
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "Connection refused" in response.error
