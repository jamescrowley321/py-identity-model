"""Unit tests for Device Authorization Grant (RFC 8628)."""

import httpx
import pytest
import respx

from py_identity_model import (
    BaseRequest,
    BaseResponse,
    DeviceAuthorizationRequest,
    DeviceAuthorizationResponse,
    DeviceTokenRequest,
    DeviceTokenResponse,
)
from py_identity_model.sync.device_auth import (
    poll_device_token,
    request_device_authorization,
)


DEVICE_AUTH_URL = "https://auth.example.com/device/authorize"
TOKEN_URL = "https://auth.example.com/token"

DEVICE_AUTH_RESPONSE = {
    "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
    "user_code": "WDJB-MJHT",
    "verification_uri": "https://auth.example.com/device",
    "verification_uri_complete": "https://auth.example.com/device?user_code=WDJB-MJHT",
    "expires_in": 1800,
    "interval": 5,
}


@pytest.mark.unit
class TestRequestDeviceAuthorization:
    @respx.mock
    def test_successful_device_auth(self):
        respx.post(DEVICE_AUTH_URL).mock(
            return_value=httpx.Response(200, json=DEVICE_AUTH_RESPONSE)
        )
        response = request_device_authorization(
            DeviceAuthorizationRequest(
                address=DEVICE_AUTH_URL,
                client_id="app1",
                client_secret="secret",
            )
        )
        assert response.is_successful is True
        assert response.device_code == DEVICE_AUTH_RESPONSE["device_code"]
        assert response.user_code == "WDJB-MJHT"
        assert response.verification_uri == "https://auth.example.com/device"
        assert response.verification_uri_complete is not None
        assert response.expires_in == 1800
        assert response.interval == 5

    @respx.mock
    def test_device_auth_without_client_secret(self):
        respx.post(DEVICE_AUTH_URL).mock(
            return_value=httpx.Response(200, json=DEVICE_AUTH_RESPONSE)
        )
        response = request_device_authorization(
            DeviceAuthorizationRequest(
                address=DEVICE_AUTH_URL,
                client_id="public-app",
                scope="openid profile",
            )
        )
        assert response.is_successful is True
        assert response.user_code == "WDJB-MJHT"

    @respx.mock
    def test_device_auth_error(self):
        respx.post(DEVICE_AUTH_URL).mock(
            return_value=httpx.Response(
                400, content=b'{"error":"unauthorized_client"}'
            )
        )
        response = request_device_authorization(
            DeviceAuthorizationRequest(
                address=DEVICE_AUTH_URL,
                client_id="bad-app",
            )
        )
        assert response.is_successful is False

    def test_request_inherits_base(self):
        req = DeviceAuthorizationRequest(
            address=DEVICE_AUTH_URL, client_id="app"
        )
        assert isinstance(req, BaseRequest)

    def test_response_inherits_base(self):
        resp = DeviceAuthorizationResponse(
            is_successful=True,
            device_code="code",
            user_code="ABCD-EFGH",
            verification_uri="https://example.com/device",
            expires_in=1800,
        )
        assert isinstance(resp, BaseResponse)


@pytest.mark.unit
class TestPollDeviceToken:
    @respx.mock
    def test_successful_token(self):
        token_data = {
            "access_token": "SlAV32hkKG",
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=token_data)
        )
        response = poll_device_token(
            DeviceTokenRequest(
                address=TOKEN_URL,
                client_id="app1",
                device_code="device123",
            )
        )
        assert response.is_successful is True
        assert response.token is not None
        assert response.token["access_token"] == "SlAV32hkKG"
        assert response.error_code is None

    @respx.mock
    def test_authorization_pending(self):
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                400,
                json={
                    "error": "authorization_pending",
                    "error_description": "The user has not yet completed authorization",
                },
            )
        )
        response = poll_device_token(
            DeviceTokenRequest(
                address=TOKEN_URL,
                client_id="app1",
                device_code="device123",
            )
        )
        assert response.is_successful is False
        assert response.error_code == "authorization_pending"

    @respx.mock
    def test_slow_down(self):
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                400,
                json={
                    "error": "slow_down",
                    "interval": 10,
                },
            )
        )
        response = poll_device_token(
            DeviceTokenRequest(
                address=TOKEN_URL,
                client_id="app1",
                device_code="device123",
            )
        )
        assert response.is_successful is False
        assert response.error_code == "slow_down"
        assert response.interval == 10

    @respx.mock
    def test_expired_token(self):
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                400,
                json={
                    "error": "expired_token",
                    "error_description": "The device code has expired",
                },
            )
        )
        response = poll_device_token(
            DeviceTokenRequest(
                address=TOKEN_URL,
                client_id="app1",
                device_code="device123",
            )
        )
        assert response.is_successful is False
        assert response.error_code == "expired_token"

    @respx.mock
    def test_access_denied(self):
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                400,
                json={
                    "error": "access_denied",
                    "error_description": "The user denied the request",
                },
            )
        )
        response = poll_device_token(
            DeviceTokenRequest(
                address=TOKEN_URL,
                client_id="app1",
                device_code="device123",
            )
        )
        assert response.is_successful is False
        assert response.error_code == "access_denied"

    @respx.mock
    def test_non_json_error_response(self):
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(500, content=b"Internal Server Error")
        )
        response = poll_device_token(
            DeviceTokenRequest(
                address=TOKEN_URL,
                client_id="app1",
                device_code="device123",
            )
        )
        assert response.is_successful is False
        assert response.error_code is None

    def test_token_request_inherits_base(self):
        req = DeviceTokenRequest(
            address=TOKEN_URL, client_id="app", device_code="code123"
        )
        assert isinstance(req, BaseRequest)

    def test_token_response_inherits_base(self):
        resp = DeviceTokenResponse(
            is_successful=True, token={"access_token": "tok"}
        )
        assert isinstance(resp, BaseResponse)
