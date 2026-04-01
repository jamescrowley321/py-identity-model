"""Integration tests for Device Authorization (RFC 8628) and Token Exchange (RFC 8693).

These tests hit a live OIDC provider.  Each test is gated on the
relevant provider capability detected from the discovery document.
"""

import pytest

from py_identity_model import (
    DeviceAuthorizationRequest,
    DeviceTokenRequest,
    TokenExchangeRequest,
)
from py_identity_model.core import token_type
from py_identity_model.sync.device_auth import (
    poll_device_token,
    request_device_authorization,
)
from py_identity_model.sync.token_exchange import exchange_token


# ============================================================================
# Device Authorization (RFC 8628)
# ============================================================================


@pytest.mark.integration
class TestDeviceAuthLive:
    """Test Device Authorization Grant against a live provider.

    The full flow requires user interaction at the verification_uri,
    so we can only test the initial authorization request and the
    polling behaviour (which returns authorization_pending).
    """

    def _request_device_auth(self, raw_discovery, test_config):
        """Request device authorization; skip if client lacks the grant."""
        endpoint = raw_discovery["device_authorization_endpoint"]

        response = request_device_authorization(
            DeviceAuthorizationRequest(
                address=endpoint,
                client_id=test_config["TEST_CLIENT_ID"],
                scope=test_config.get("TEST_SCOPE", "openid"),
                client_secret=test_config.get("TEST_CLIENT_SECRET"),
            )
        )

        # The provider may expose the endpoint but the test client may
        # not have the device_code grant assigned.
        if not response.is_successful and "invalid_grant" in str(response.error):
            pytest.skip("Test client does not have device_code grant assigned")

        return response

    def test_request_device_authorization(
        self,
        provider_capabilities,
        raw_discovery,
        test_config,
    ):
        """Request device authorization and receive device/user codes."""
        if "device_authorization" not in provider_capabilities:
            pytest.skip("Provider does not support device authorization grant")
        if "device_authorization_endpoint" not in provider_capabilities:
            pytest.skip("Provider does not expose device_authorization_endpoint")

        response = self._request_device_auth(raw_discovery, test_config)

        assert response.is_successful is True, f"Device auth failed: {response.error}"
        assert response.device_code is not None
        assert response.user_code is not None
        assert response.verification_uri is not None
        assert response.expires_in is not None
        assert response.expires_in > 0

    def test_poll_returns_authorization_pending(
        self,
        provider_capabilities,
        raw_discovery,
        test_config,
        token_endpoint,
    ):
        """Polling before user authorizes returns authorization_pending."""
        if "device_authorization" not in provider_capabilities:
            pytest.skip("Provider does not support device authorization grant")
        if "device_authorization_endpoint" not in provider_capabilities:
            pytest.skip("Provider does not expose device_authorization_endpoint")

        auth_response = self._request_device_auth(raw_discovery, test_config)
        assert auth_response.is_successful is True
        assert auth_response.device_code is not None

        # Poll immediately — user hasn't authorized yet
        poll_response = poll_device_token(
            DeviceTokenRequest(
                address=token_endpoint,
                client_id=test_config["TEST_CLIENT_ID"],
                device_code=auth_response.device_code,
                client_secret=test_config.get("TEST_CLIENT_SECRET"),
            )
        )

        # Should be pending (not successful yet)
        assert poll_response.is_successful is False
        assert poll_response.error_code in (
            "authorization_pending",
            "slow_down",
        )

    def test_poll_invalid_device_code(
        self,
        provider_capabilities,
        test_config,
        token_endpoint,
    ):
        """Polling with an invalid device code returns an error."""
        if "device_authorization" not in provider_capabilities:
            pytest.skip("Provider does not support device authorization grant")

        response = poll_device_token(
            DeviceTokenRequest(
                address=token_endpoint,
                client_id=test_config["TEST_CLIENT_ID"],
                device_code="invalid-device-code-value",
                client_secret=test_config.get("TEST_CLIENT_SECRET"),
            )
        )

        assert response.is_successful is False
        assert response.error is not None


# ============================================================================
# Token Exchange (RFC 8693)
# ============================================================================


@pytest.mark.integration
class TestTokenExchangeLive:
    """Test Token Exchange against a live provider."""

    def test_exchange_access_token(
        self,
        provider_capabilities,
        token_endpoint,
        client_credentials_token,
        test_config,
    ):
        """Exchange a valid access token for a new token."""
        if "token_exchange" not in provider_capabilities:
            pytest.skip("Provider does not support token exchange grant")

        access_token = client_credentials_token.token["access_token"]

        response = exchange_token(
            TokenExchangeRequest(
                address=token_endpoint,
                client_id=test_config["TEST_CLIENT_ID"],
                subject_token=access_token,
                subject_token_type=token_type.ACCESS_TOKEN,
                client_secret=test_config.get("TEST_CLIENT_SECRET"),
            )
        )

        assert response.is_successful is True, (
            f"Token exchange failed: {response.error}"
        )
        assert response.token is not None
        assert "access_token" in response.token
        assert response.issued_token_type is not None

    def test_exchange_with_audience(
        self,
        provider_capabilities,
        token_endpoint,
        client_credentials_token,
        test_config,
    ):
        """Exchange token with target audience."""
        if "token_exchange" not in provider_capabilities:
            pytest.skip("Provider does not support token exchange grant")

        access_token = client_credentials_token.token["access_token"]

        response = exchange_token(
            TokenExchangeRequest(
                address=token_endpoint,
                client_id=test_config["TEST_CLIENT_ID"],
                subject_token=access_token,
                subject_token_type=token_type.ACCESS_TOKEN,
                audience=test_config.get("TEST_AUDIENCE", ""),
                client_secret=test_config.get("TEST_CLIENT_SECRET"),
            )
        )

        # Provider may accept or reject audience-scoped exchange
        if response.is_successful:
            assert response.token is not None
            assert "access_token" in response.token
        else:
            assert response.error is not None

    def test_exchange_invalid_token(
        self,
        provider_capabilities,
        token_endpoint,
        test_config,
    ):
        """Exchange with invalid subject token returns error."""
        if "token_exchange" not in provider_capabilities:
            pytest.skip("Provider does not support token exchange grant")

        response = exchange_token(
            TokenExchangeRequest(
                address=token_endpoint,
                client_id=test_config["TEST_CLIENT_ID"],
                subject_token="invalid-token-value",
                subject_token_type=token_type.ACCESS_TOKEN,
                client_secret=test_config.get("TEST_CLIENT_SECRET"),
            )
        )

        assert response.is_successful is False
        assert response.error is not None
