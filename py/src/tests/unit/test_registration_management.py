"""Unit tests for RFC 7592 client management (read / update / delete).

Covers spec IDs:
- DYN-003: read a registered client via the registration access token
plus the full RFC 7592 CRUD surface (update, delete).
"""

import httpx
import pytest
import respx

import py_identity_model
from py_identity_model import (
    ClientDeleteRequest,
    ClientDeleteResponse,
    ClientReadRequest,
    ClientUpdateRequest,
    delete_client,
    read_client,
    update_client,
)
import py_identity_model.aio as pim_aio
from py_identity_model.aio.registration import delete_client as async_delete_client
from py_identity_model.aio.registration import read_client as async_read_client
from py_identity_model.aio.registration import update_client as async_update_client


CLIENT_URI = "https://auth.example.com/register/s6BhdRkqt3"
REG_TOKEN = "reg-23410913-abewfq.123483"

CLIENT_CONFIG = {
    "client_id": "s6BhdRkqt3",
    "client_secret": "cf136dc3c1fc93f31185e5885805d",
    "registration_access_token": REG_TOKEN,
    "registration_client_uri": CLIENT_URI,
    "redirect_uris": ["https://app.example.com/cb"],
    "client_name": "Example Client",
}


@pytest.mark.unit
class TestReadClient:
    @respx.mock
    def test_read_client(self):
        # DYN-003: read returns the current client configuration.
        respx.get(CLIENT_URI).mock(return_value=httpx.Response(200, json=CLIENT_CONFIG))
        response = read_client(
            ClientReadRequest(
                address=CLIENT_URI,
                registration_access_token=REG_TOKEN,
            )
        )
        assert response.is_successful is True
        assert response.client_id == "s6BhdRkqt3"
        assert response.metadata is not None
        assert response.metadata["client_name"] == "Example Client"

    @respx.mock
    def test_read_client_sends_bearer_token(self):
        # DYN-003: the registration access token is sent as a Bearer header.
        route = respx.get(CLIENT_URI).mock(
            return_value=httpx.Response(200, json=CLIENT_CONFIG)
        )
        read_client(
            ClientReadRequest(
                address=CLIENT_URI,
                registration_access_token=REG_TOKEN,
            )
        )
        request = route.calls[0].request
        assert request.headers["authorization"] == f"Bearer {REG_TOKEN}"

    @respx.mock
    def test_read_client_invalid_token(self):
        respx.get(CLIENT_URI).mock(
            return_value=httpx.Response(401, json={"error": "invalid_token"})
        )
        response = read_client(
            ClientReadRequest(
                address=CLIENT_URI,
                registration_access_token="wrong",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "invalid_token" in response.error


@pytest.mark.unit
class TestUpdateClient:
    @respx.mock
    def test_update_client(self):
        updated = {**CLIENT_CONFIG, "client_name": "Renamed Client"}
        route = respx.put(CLIENT_URI).mock(
            return_value=httpx.Response(200, json=updated)
        )
        response = update_client(
            ClientUpdateRequest(
                address=CLIENT_URI,
                registration_access_token=REG_TOKEN,
                client_id="s6BhdRkqt3",
                redirect_uris=["https://app.example.com/cb"],
                client_name="Renamed Client",
            )
        )
        assert response.is_successful is True
        assert response.metadata is not None
        assert response.metadata["client_name"] == "Renamed Client"
        # RFC 7592 §2.2: PUT body MUST include client_id + full metadata.
        request = route.calls[0].request
        assert request.headers["authorization"] == f"Bearer {REG_TOKEN}"
        assert request.headers["content-type"] == "application/json"
        body = request.content.decode()
        assert '"client_id"' in body
        assert "Renamed Client" in body

    @respx.mock
    def test_update_client_error(self):
        respx.put(CLIENT_URI).mock(
            return_value=httpx.Response(400, json={"error": "invalid_client_metadata"})
        )
        response = update_client(
            ClientUpdateRequest(
                address=CLIENT_URI,
                registration_access_token=REG_TOKEN,
                client_id="s6BhdRkqt3",
                redirect_uris=["https://app.example.com/cb"],
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "invalid_client_metadata" in response.error


@pytest.mark.unit
class TestDeleteClient:
    @respx.mock
    def test_delete_client_204(self):
        # RFC 7592 §2.3: successful deregistration returns 204 No Content.
        route = respx.delete(CLIENT_URI).mock(return_value=httpx.Response(204))
        response = delete_client(
            ClientDeleteRequest(
                address=CLIENT_URI,
                registration_access_token=REG_TOKEN,
            )
        )
        assert response.is_successful is True
        request = route.calls[0].request
        assert request.headers["authorization"] == f"Bearer {REG_TOKEN}"

    @respx.mock
    def test_delete_client_200(self):
        # Some providers respond 200 to a delete; still a success.
        respx.delete(CLIENT_URI).mock(return_value=httpx.Response(200))
        response = delete_client(
            ClientDeleteRequest(
                address=CLIENT_URI,
                registration_access_token=REG_TOKEN,
            )
        )
        assert response.is_successful is True

    @respx.mock
    def test_delete_client_error(self):
        respx.delete(CLIENT_URI).mock(
            return_value=httpx.Response(403, json={"error": "invalid_token"})
        )
        response = delete_client(
            ClientDeleteRequest(
                address=CLIENT_URI,
                registration_access_token="wrong",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "invalid_token" in response.error

    @respx.mock
    def test_delete_client_network_error(self):
        respx.delete(CLIENT_URI).mock(
            side_effect=httpx.ConnectError("Connection refused")
        )
        response = delete_client(
            ClientDeleteRequest(
                address=CLIENT_URI,
                registration_access_token=REG_TOKEN,
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "Connection refused" in response.error

    def test_delete_response_type(self):
        resp = ClientDeleteResponse(is_successful=True)
        assert resp.is_successful is True


@pytest.mark.unit
class TestManagementExportIdentity:
    def test_crud_public_from_sync_and_aio(self):
        for name in ("read_client", "update_client", "delete_client"):
            assert name in py_identity_model.__all__
            assert name in pim_aio.__all__
            assert callable(getattr(py_identity_model, name))
            assert callable(getattr(pim_aio, name))


@pytest.mark.asyncio
class TestAsyncClientManagement:
    @respx.mock
    async def test_read_client(self):
        # DYN-003 (async parity)
        respx.get(CLIENT_URI).mock(return_value=httpx.Response(200, json=CLIENT_CONFIG))
        response = await async_read_client(
            ClientReadRequest(
                address=CLIENT_URI,
                registration_access_token=REG_TOKEN,
            )
        )
        assert response.is_successful is True
        assert response.client_id == "s6BhdRkqt3"

    @respx.mock
    async def test_update_client(self):
        updated = {**CLIENT_CONFIG, "client_name": "Renamed Client"}
        route = respx.put(CLIENT_URI).mock(
            return_value=httpx.Response(200, json=updated)
        )
        response = await async_update_client(
            ClientUpdateRequest(
                address=CLIENT_URI,
                registration_access_token=REG_TOKEN,
                client_id="s6BhdRkqt3",
                redirect_uris=["https://app.example.com/cb"],
                client_name="Renamed Client",
            )
        )
        assert response.is_successful is True
        assert response.metadata is not None
        assert response.metadata["client_name"] == "Renamed Client"
        assert route.calls[0].request.headers["authorization"] == f"Bearer {REG_TOKEN}"

    @respx.mock
    async def test_delete_client_204(self):
        respx.delete(CLIENT_URI).mock(return_value=httpx.Response(204))
        response = await async_delete_client(
            ClientDeleteRequest(
                address=CLIENT_URI,
                registration_access_token=REG_TOKEN,
            )
        )
        assert response.is_successful is True

    @respx.mock
    async def test_delete_client_error(self):
        respx.delete(CLIENT_URI).mock(
            return_value=httpx.Response(403, json={"error": "invalid_token"})
        )
        response = await async_delete_client(
            ClientDeleteRequest(
                address=CLIENT_URI,
                registration_access_token="wrong",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "invalid_token" in response.error
