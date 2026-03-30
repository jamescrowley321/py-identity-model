"""Integration tests for Device Authorization Grant (RFC 8628)."""

import pytest

from py_identity_model import (
    BaseRequest,
    DeviceAuthorizationRequest,
    DeviceAuthorizationResponse,
    DeviceTokenRequest,
    DeviceTokenResponse,
    FailedResponseAccessError,
)
from py_identity_model.core.device_auth_logic import (
    prepare_device_auth_request_data,
    prepare_device_token_request_data,
)


@pytest.mark.integration
class TestDeviceAuthIntegration:
    def test_device_auth_request_model(self):
        req = DeviceAuthorizationRequest(
            address="https://auth.example.com/device/authorize",
            client_id="cli-app",
            scope="openid profile offline_access",
        )
        assert isinstance(req, BaseRequest)
        assert req.scope == "openid profile offline_access"
        assert req.client_secret is None

    def test_device_auth_request_with_secret(self):
        req = DeviceAuthorizationRequest(
            address="https://auth.example.com/device/authorize",
            client_id="confidential-app",
            client_secret="s3cret",
        )
        assert req.client_secret == "s3cret"

    def test_device_auth_response_guarded_fields(self):
        resp = DeviceAuthorizationResponse(
            is_successful=False,
            error="unauthorized_client",
        )
        with pytest.raises(FailedResponseAccessError):
            _ = resp.device_code
        with pytest.raises(FailedResponseAccessError):
            _ = resp.user_code

    def test_device_auth_response_success(self):
        resp = DeviceAuthorizationResponse(
            is_successful=True,
            device_code="dev123",
            user_code="ABCD-EFGH",
            verification_uri="https://auth.example.com/device",
            expires_in=1800,
            interval=5,
        )
        assert resp.device_code == "dev123"
        assert resp.user_code == "ABCD-EFGH"
        assert resp.interval == 5

    def test_device_token_request_model(self):
        req = DeviceTokenRequest(
            address="https://auth.example.com/token",
            client_id="cli-app",
            device_code="device_code_123",
        )
        assert isinstance(req, BaseRequest)
        assert req.device_code == "device_code_123"

    def test_device_token_response_pending(self):
        resp = DeviceTokenResponse(
            is_successful=False,
            error="User hasn't authorized yet",
            error_code="authorization_pending",
        )
        assert resp.error_code == "authorization_pending"
        assert resp.interval is None

    def test_device_token_response_slow_down(self):
        resp = DeviceTokenResponse(
            is_successful=False,
            error="Slow down",
            error_code="slow_down",
            interval=10,
        )
        assert resp.error_code == "slow_down"
        assert resp.interval == 10

    def test_device_token_response_success(self):
        resp = DeviceTokenResponse(
            is_successful=True,
            token={"access_token": "at123", "token_type": "Bearer"},
        )
        assert resp.token is not None
        assert resp.token["access_token"] == "at123"
        assert resp.error_code is None

    def test_prepare_device_auth_data_public_client(self):
        req = DeviceAuthorizationRequest(
            address="https://auth.example.com/device/authorize",
            client_id="public-app",
            scope="openid",
        )
        data, headers, auth = prepare_device_auth_request_data(req)
        assert data["client_id"] == "public-app"
        assert data["scope"] == "openid"
        assert headers["Content-Type"] == "application/x-www-form-urlencoded"
        assert auth is None

    def test_prepare_device_auth_data_confidential_client(self):
        req = DeviceAuthorizationRequest(
            address="https://auth.example.com/device/authorize",
            client_id="conf-app",
            client_secret="secret",
        )
        _data, _headers, auth = prepare_device_auth_request_data(req)
        assert auth == ("conf-app", "secret")

    def test_prepare_device_token_data(self):
        req = DeviceTokenRequest(
            address="https://auth.example.com/token",
            client_id="app",
            device_code="dev_code_xyz",
        )
        data, _headers, auth = prepare_device_token_request_data(req)
        assert (
            data["grant_type"]
            == "urn:ietf:params:oauth:grant-type:device_code"
        )
        assert data["device_code"] == "dev_code_xyz"
        assert data["client_id"] == "app"
        assert auth is None

    def test_top_level_import(self):
        from py_identity_model import (
            DeviceAuthorizationRequest,
            DeviceAuthorizationResponse,
            DeviceTokenRequest,
            DeviceTokenResponse,
            poll_device_token,
            request_device_authorization,
        )

        assert callable(request_device_authorization)
        assert callable(poll_device_token)
        assert DeviceAuthorizationRequest is not None
        assert DeviceAuthorizationResponse is not None
        assert DeviceTokenRequest is not None
        assert DeviceTokenResponse is not None

    def test_aio_import(self):
        from py_identity_model.aio import (
            DeviceAuthorizationRequest,
            DeviceAuthorizationResponse,
            DeviceTokenRequest,
            DeviceTokenResponse,
            poll_device_token,
            request_device_authorization,
        )

        assert callable(request_device_authorization)
        assert callable(poll_device_token)
        assert DeviceAuthorizationRequest is not None
        assert DeviceAuthorizationResponse is not None
        assert DeviceTokenRequest is not None
        assert DeviceTokenResponse is not None
