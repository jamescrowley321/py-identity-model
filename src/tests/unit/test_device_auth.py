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

    @respx.mock
    def test_missing_required_fields_returns_error(self):
        """S2: Missing REQUIRED fields per RFC 8628 §3.2 return error."""
        respx.post(DEVICE_AUTH_URL).mock(
            return_value=httpx.Response(200, json={})
        )
        response = request_device_authorization(
            DeviceAuthorizationRequest(
                address=DEVICE_AUTH_URL,
                client_id="app1",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "device_code" in response.error
        assert "user_code" in response.error
        assert "verification_uri" in response.error
        assert "expires_in" in response.error

    @respx.mock
    def test_missing_device_code_returns_error(self):
        """S2: Partial REQUIRED fields still fail."""
        partial = {**DEVICE_AUTH_RESPONSE}
        del partial["device_code"]
        respx.post(DEVICE_AUTH_URL).mock(
            return_value=httpx.Response(200, json=partial)
        )
        response = request_device_authorization(
            DeviceAuthorizationRequest(
                address=DEVICE_AUTH_URL,
                client_id="app1",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "device_code" in response.error

    @respx.mock
    def test_expires_in_string_returns_error(self):
        """S3: expires_in must be a positive integer per RFC 8628 §3.2."""
        bad_response = {**DEVICE_AUTH_RESPONSE, "expires_in": "1800"}
        respx.post(DEVICE_AUTH_URL).mock(
            return_value=httpx.Response(200, json=bad_response)
        )
        response = request_device_authorization(
            DeviceAuthorizationRequest(
                address=DEVICE_AUTH_URL,
                client_id="app1",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "expires_in" in response.error

    @respx.mock
    def test_expires_in_zero_returns_error(self):
        """S3: expires_in=0 is invalid."""
        bad_response = {**DEVICE_AUTH_RESPONSE, "expires_in": 0}
        respx.post(DEVICE_AUTH_URL).mock(
            return_value=httpx.Response(200, json=bad_response)
        )
        response = request_device_authorization(
            DeviceAuthorizationRequest(
                address=DEVICE_AUTH_URL,
                client_id="app1",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "expires_in" in response.error

    @respx.mock
    def test_interval_float_coerced_to_int(self):
        """S3: float interval is coerced to int."""
        float_response = {**DEVICE_AUTH_RESPONSE, "interval": 5.5}
        respx.post(DEVICE_AUTH_URL).mock(
            return_value=httpx.Response(200, json=float_response)
        )
        response = request_device_authorization(
            DeviceAuthorizationRequest(
                address=DEVICE_AUTH_URL,
                client_id="app1",
            )
        )
        assert response.is_successful is True
        assert response.interval == 5
        assert isinstance(response.interval, int)

    @respx.mock
    def test_interval_string_becomes_none(self):
        """S3: non-numeric interval is treated as absent."""
        bad_response = {**DEVICE_AUTH_RESPONSE, "interval": "five"}
        respx.post(DEVICE_AUTH_URL).mock(
            return_value=httpx.Response(200, json=bad_response)
        )
        response = request_device_authorization(
            DeviceAuthorizationRequest(
                address=DEVICE_AUTH_URL,
                client_id="app1",
            )
        )
        assert response.is_successful is True
        assert response.interval is None

    @respx.mock
    def test_non_json_success_returns_error(self):
        """M1: Non-JSON body on 200 returns error instead of crashing."""
        respx.post(DEVICE_AUTH_URL).mock(
            return_value=httpx.Response(
                200, content=b"<html>Gateway Error</html>"
            )
        )
        response = request_device_authorization(
            DeviceAuthorizationRequest(
                address=DEVICE_AUTH_URL,
                client_id="app1",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "invalid JSON" in response.error

    @respx.mock
    def test_non_dict_json_success_returns_error(self):
        """Edge: Non-dict JSON on 200 returns error instead of AttributeError."""
        respx.post(DEVICE_AUTH_URL).mock(
            return_value=httpx.Response(200, json=["not", "a", "dict"])
        )
        response = request_device_authorization(
            DeviceAuthorizationRequest(
                address=DEVICE_AUTH_URL,
                client_id="app1",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "not a JSON object" in response.error

    @respx.mock
    def test_expires_in_float_coerced_to_int(self):
        """M2: float expires_in is coerced to int (JSON has no int/float distinction)."""
        float_response = {**DEVICE_AUTH_RESPONSE, "expires_in": 1800.0}
        respx.post(DEVICE_AUTH_URL).mock(
            return_value=httpx.Response(200, json=float_response)
        )
        response = request_device_authorization(
            DeviceAuthorizationRequest(
                address=DEVICE_AUTH_URL,
                client_id="app1",
            )
        )
        assert response.is_successful is True
        assert response.expires_in == 1800
        assert isinstance(response.expires_in, int)


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
    def test_slow_down_float_interval(self):
        """S3: float interval in slow_down response is coerced to int."""
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                400,
                json={
                    "error": "slow_down",
                    "interval": 10.5,
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
        assert isinstance(response.interval, int)

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

    @respx.mock
    def test_non_json_token_success_returns_error(self):
        """M1: Non-JSON body on 200 token response returns error."""
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, content=b"<html>Error</html>")
        )
        response = poll_device_token(
            DeviceTokenRequest(
                address=TOKEN_URL,
                client_id="app1",
                device_code="device123",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "invalid JSON" in response.error

    @respx.mock
    def test_non_dict_json_token_success_returns_error(self):
        """WARN3: Non-dict JSON on 200 token response returns error."""
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=["not", "a", "dict"])
        )
        response = poll_device_token(
            DeviceTokenRequest(
                address=TOKEN_URL,
                client_id="app1",
                device_code="device123",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "not a JSON object" in response.error

    @respx.mock
    def test_non_dict_json_error_response(self):
        """WARN4: Non-dict JSON on error response handled gracefully."""
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(400, json=["error_array"])
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
