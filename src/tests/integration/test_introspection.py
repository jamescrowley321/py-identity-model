"""Integration tests for OAuth 2.0 Token Introspection (RFC 7662).

Tests exercise the full introspection protocol against a live OIDC
provider.  Constructor/model tests belong in unit tests — this file
only contains tests that require a running provider.
"""

import httpx
import pytest

from py_identity_model import (
    TokenIntrospectionRequest,
    TokenRevocationRequest,
    introspect_token,
    revoke_token,
)
from py_identity_model.aio.introspection import (
    introspect_token as aio_introspect_token,
)


HTTP_OK = 200


def _require_introspection(provider_capabilities, test_config):
    if "introspection" not in provider_capabilities:
        pytest.skip("Provider does not expose introspection_endpoint")
    if not test_config.get("TEST_OPAQUE_CLIENT_ID"):
        pytest.skip("TEST_OPAQUE_CLIENT_ID not configured")


def _get_fresh_opaque_token(raw_discovery, test_config) -> str:
    """Get a fresh opaque token via direct httpx call.

    Uses the opaque client to avoid JWT tokens that some providers
    cannot introspect.  Avoids consuming the shared session fixture.
    """
    opaque_id = test_config.get("TEST_OPAQUE_CLIENT_ID")
    opaque_secret = test_config.get("TEST_OPAQUE_CLIENT_SECRET")
    if not opaque_id or not opaque_secret:
        pytest.skip("TEST_OPAQUE_CLIENT_ID not configured")

    resp = httpx.post(
        raw_discovery["token_endpoint"],
        data={
            "grant_type": "client_credentials",
            "scope": test_config.get("TEST_SCOPE", "openid"),
        },
        auth=(opaque_id, opaque_secret),
        timeout=10.0,
    )
    assert resp.status_code == HTTP_OK, (
        f"Failed to get opaque token: {resp.status_code} {resp.text}"
    )
    return resp.json()["access_token"]


@pytest.mark.integration
class TestIntrospectionSync:
    """Synchronous introspection against live provider."""

    def test_active_token(
        self,
        provider_capabilities,
        raw_discovery,
        opaque_access_token,
        test_config,
    ):
        """Introspecting a valid access token returns active=True."""
        _require_introspection(provider_capabilities, test_config)
        endpoint = raw_discovery["introspection_endpoint"]

        response = introspect_token(
            TokenIntrospectionRequest(
                address=endpoint,
                token=opaque_access_token,
                client_id=test_config["TEST_OPAQUE_CLIENT_ID"],
                client_secret=test_config["TEST_OPAQUE_CLIENT_SECRET"],
                token_type_hint="access_token",
            )
        )

        assert response.is_successful, f"Introspection failed: {response.error}"
        assert response.claims is not None
        assert response.claims["active"] is True

    def test_active_token_contains_standard_claims(
        self,
        provider_capabilities,
        raw_discovery,
        opaque_access_token,
        test_config,
    ):
        """Active token introspection includes RFC 7662 §2.2 claims."""
        _require_introspection(provider_capabilities, test_config)
        endpoint = raw_discovery["introspection_endpoint"]

        response = introspect_token(
            TokenIntrospectionRequest(
                address=endpoint,
                token=opaque_access_token,
                client_id=test_config["TEST_OPAQUE_CLIENT_ID"],
                client_secret=test_config["TEST_OPAQUE_CLIENT_SECRET"],
            )
        )

        assert response.is_successful
        claims = response.claims
        assert claims is not None
        assert claims["active"] is True
        # RFC 7662 §2.2 — active tokens SHOULD include these
        assert "client_id" in claims
        assert claims["client_id"] == test_config["TEST_OPAQUE_CLIENT_ID"]

    def test_invalid_token_returns_inactive(
        self,
        provider_capabilities,
        raw_discovery,
        test_config,
    ):
        """Introspecting a garbage token returns active=False."""
        _require_introspection(provider_capabilities, test_config)
        endpoint = raw_discovery["introspection_endpoint"]

        response = introspect_token(
            TokenIntrospectionRequest(
                address=endpoint,
                token="invalid-token-value",
                client_id=test_config["TEST_OPAQUE_CLIENT_ID"],
                client_secret=test_config["TEST_OPAQUE_CLIENT_SECRET"],
            )
        )

        assert response.is_successful
        assert response.claims is not None
        assert response.claims["active"] is False

    def test_token_type_hint_refresh_token(
        self,
        provider_capabilities,
        raw_discovery,
        test_config,
    ):
        """Introspecting with refresh_token hint on an invalid token."""
        _require_introspection(provider_capabilities, test_config)
        endpoint = raw_discovery["introspection_endpoint"]

        response = introspect_token(
            TokenIntrospectionRequest(
                address=endpoint,
                token="not-a-real-refresh-token",
                client_id=test_config["TEST_OPAQUE_CLIENT_ID"],
                client_secret=test_config["TEST_OPAQUE_CLIENT_SECRET"],
                token_type_hint="refresh_token",
            )
        )

        assert response.is_successful
        assert response.claims is not None
        assert response.claims["active"] is False

    def test_revoked_token_is_inactive(
        self,
        provider_capabilities,
        raw_discovery,
        test_config,
    ):
        """After revocation, introspection returns active=False.

        Tests the introspection+revocation interplay: revoke a token,
        then introspect to confirm the server considers it dead.
        """
        _require_introspection(provider_capabilities, test_config)
        if "revocation" not in provider_capabilities:
            pytest.skip("Provider does not expose revocation_endpoint")

        fresh_token = _get_fresh_opaque_token(raw_discovery, test_config)

        # Revoke it
        revoke_response = revoke_token(
            TokenRevocationRequest(
                address=raw_discovery["revocation_endpoint"],
                token=fresh_token,
                client_id=test_config["TEST_OPAQUE_CLIENT_ID"],
                client_secret=test_config["TEST_OPAQUE_CLIENT_SECRET"],
                token_type_hint="access_token",
            )
        )
        assert revoke_response.is_successful

        # Introspect — should be inactive
        introspect_response = introspect_token(
            TokenIntrospectionRequest(
                address=raw_discovery["introspection_endpoint"],
                token=fresh_token,
                client_id=test_config["TEST_OPAQUE_CLIENT_ID"],
                client_secret=test_config["TEST_OPAQUE_CLIENT_SECRET"],
            )
        )
        assert introspect_response.is_successful
        assert introspect_response.claims is not None
        assert introspect_response.claims["active"] is False


@pytest.mark.integration
class TestIntrospectionAsync:
    """Async introspection against live provider."""

    @pytest.mark.asyncio
    async def test_active_token(
        self,
        provider_capabilities,
        raw_discovery,
        opaque_access_token,
        test_config,
    ):
        """Async introspection of a valid token returns active=True."""
        _require_introspection(provider_capabilities, test_config)
        endpoint = raw_discovery["introspection_endpoint"]

        response = await aio_introspect_token(
            TokenIntrospectionRequest(
                address=endpoint,
                token=opaque_access_token,
                client_id=test_config["TEST_OPAQUE_CLIENT_ID"],
                client_secret=test_config["TEST_OPAQUE_CLIENT_SECRET"],
            )
        )

        assert response.is_successful, f"Async introspection failed: {response.error}"
        assert response.claims is not None
        assert response.claims["active"] is True
        assert "client_id" in response.claims

    @pytest.mark.asyncio
    async def test_invalid_token_returns_inactive(
        self,
        provider_capabilities,
        raw_discovery,
        test_config,
    ):
        """Async introspection of garbage token returns active=False."""
        _require_introspection(provider_capabilities, test_config)
        endpoint = raw_discovery["introspection_endpoint"]

        response = await aio_introspect_token(
            TokenIntrospectionRequest(
                address=endpoint,
                token="garbage-token-async",
                client_id=test_config["TEST_OPAQUE_CLIENT_ID"],
                client_secret=test_config["TEST_OPAQUE_CLIENT_SECRET"],
            )
        )

        assert response.is_successful
        assert response.claims is not None
        assert response.claims["active"] is False
