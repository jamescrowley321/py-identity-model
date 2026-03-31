"""Integration tests for OAuth 2.0 Token Revocation (RFC 7009).

Tests exercise the full revocation protocol against a live OIDC
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
from py_identity_model.aio.revocation import (
    revoke_token as aio_revoke_token,
)


HTTP_OK = 200


def _require_revocation(provider_capabilities):
    if "revocation" not in provider_capabilities:
        pytest.skip("Provider does not expose revocation_endpoint")


def _get_fresh_opaque_token(raw_discovery, test_config) -> str:
    """Get a fresh opaque token via direct httpx call.

    Uses the opaque client to avoid JWT tokens that some providers
    cannot revoke.  Avoids consuming the shared session fixture.
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
class TestRevocationSync:
    """Synchronous revocation against live provider."""

    def test_revoke_valid_token(
        self,
        provider_capabilities,
        raw_discovery,
        test_config,
    ):
        """Revoking a valid access token succeeds (RFC 7009 §2.1)."""
        _require_revocation(provider_capabilities)
        token = _get_fresh_opaque_token(raw_discovery, test_config)

        response = revoke_token(
            TokenRevocationRequest(
                address=raw_discovery["revocation_endpoint"],
                token=token,
                client_id=test_config["TEST_OPAQUE_CLIENT_ID"],
                client_secret=test_config["TEST_OPAQUE_CLIENT_SECRET"],
                token_type_hint="access_token",
            )
        )

        assert response.is_successful, f"Revocation failed: {response.error}"

    def test_revoke_invalid_token_succeeds(
        self,
        provider_capabilities,
        raw_discovery,
        test_config,
    ):
        """Revoking an invalid token still returns 200 (RFC 7009 §2.1).

        The server MUST respond with HTTP 200 for both valid and invalid
        tokens to prevent token scanning attacks.
        """
        _require_revocation(provider_capabilities)

        response = revoke_token(
            TokenRevocationRequest(
                address=raw_discovery["revocation_endpoint"],
                token="invalid-token-not-real",
                client_id=test_config["TEST_OPAQUE_CLIENT_ID"],
                client_secret=test_config["TEST_OPAQUE_CLIENT_SECRET"],
            )
        )

        assert response.is_successful

    def test_revoked_token_fails_introspection(
        self,
        provider_capabilities,
        raw_discovery,
        test_config,
    ):
        """Revoked token is inactive when introspected."""
        _require_revocation(provider_capabilities)
        if "introspection" not in provider_capabilities:
            pytest.skip("Provider does not expose introspection_endpoint")

        token = _get_fresh_opaque_token(raw_discovery, test_config)

        # Verify active before revocation
        pre_response = introspect_token(
            TokenIntrospectionRequest(
                address=raw_discovery["introspection_endpoint"],
                token=token,
                client_id=test_config["TEST_OPAQUE_CLIENT_ID"],
                client_secret=test_config["TEST_OPAQUE_CLIENT_SECRET"],
            )
        )
        assert pre_response.is_successful
        assert pre_response.claims is not None
        assert pre_response.claims["active"] is True

        # Revoke
        revoke_response = revoke_token(
            TokenRevocationRequest(
                address=raw_discovery["revocation_endpoint"],
                token=token,
                client_id=test_config["TEST_OPAQUE_CLIENT_ID"],
                client_secret=test_config["TEST_OPAQUE_CLIENT_SECRET"],
                token_type_hint="access_token",
            )
        )
        assert revoke_response.is_successful

        # Verify inactive after revocation
        post_response = introspect_token(
            TokenIntrospectionRequest(
                address=raw_discovery["introspection_endpoint"],
                token=token,
                client_id=test_config["TEST_OPAQUE_CLIENT_ID"],
                client_secret=test_config["TEST_OPAQUE_CLIENT_SECRET"],
            )
        )
        assert post_response.is_successful
        assert post_response.claims is not None
        assert post_response.claims["active"] is False

    def test_revoke_with_token_type_hint(
        self,
        provider_capabilities,
        raw_discovery,
        test_config,
    ):
        """Revocation with explicit token_type_hint=access_token."""
        _require_revocation(provider_capabilities)
        token = _get_fresh_opaque_token(raw_discovery, test_config)

        response = revoke_token(
            TokenRevocationRequest(
                address=raw_discovery["revocation_endpoint"],
                token=token,
                client_id=test_config["TEST_OPAQUE_CLIENT_ID"],
                client_secret=test_config["TEST_OPAQUE_CLIENT_SECRET"],
                token_type_hint="access_token",
            )
        )

        assert response.is_successful

    def test_double_revocation_succeeds(
        self,
        provider_capabilities,
        raw_discovery,
        test_config,
    ):
        """Revoking an already-revoked token still succeeds.

        RFC 7009 §2.1: The authorization server responds with HTTP 200
        for both valid and already-invalidated tokens.
        """
        _require_revocation(provider_capabilities)
        token = _get_fresh_opaque_token(raw_discovery, test_config)
        endpoint = raw_discovery["revocation_endpoint"]

        request = TokenRevocationRequest(
            address=endpoint,
            token=token,
            client_id=test_config["TEST_OPAQUE_CLIENT_ID"],
            client_secret=test_config["TEST_OPAQUE_CLIENT_SECRET"],
        )

        first = revoke_token(request)
        assert first.is_successful

        second = revoke_token(request)
        assert second.is_successful


@pytest.mark.integration
class TestRevocationAsync:
    """Async revocation against live provider."""

    @pytest.mark.asyncio
    async def test_revoke_valid_token(
        self,
        provider_capabilities,
        raw_discovery,
        test_config,
    ):
        """Async revocation of a valid token succeeds."""
        _require_revocation(provider_capabilities)
        token = _get_fresh_opaque_token(raw_discovery, test_config)

        response = await aio_revoke_token(
            TokenRevocationRequest(
                address=raw_discovery["revocation_endpoint"],
                token=token,
                client_id=test_config["TEST_OPAQUE_CLIENT_ID"],
                client_secret=test_config["TEST_OPAQUE_CLIENT_SECRET"],
                token_type_hint="access_token",
            )
        )

        assert response.is_successful, f"Async revocation failed: {response.error}"

    @pytest.mark.asyncio
    async def test_revoke_invalid_token_succeeds(
        self,
        provider_capabilities,
        raw_discovery,
        test_config,
    ):
        """Async revocation of invalid token still succeeds."""
        _require_revocation(provider_capabilities)

        response = await aio_revoke_token(
            TokenRevocationRequest(
                address=raw_discovery["revocation_endpoint"],
                token="async-invalid-token",
                client_id=test_config["TEST_OPAQUE_CLIENT_ID"],
                client_secret=test_config["TEST_OPAQUE_CLIENT_SECRET"],
            )
        )

        assert response.is_successful
