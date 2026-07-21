"""Live integration tests for Dynamic Client Registration (RFC 7591 / 7592).

Exercises the full register -> read -> update -> delete lifecycle against a
running provider's ``registration_endpoint``. Provider-agnostic and
capability-gated: runs where the provider advertises a registration endpoint
and the RP can obtain a credential to use it, and skips cleanly otherwise.
Model/parsing tests live in the unit suite; this file only covers the live
protocol round-trip.

Keycloak protects its registration endpoint, so the RP mints a one-shot
client-registration *initial access token* via the admin REST API (admin
creds from ``TEST_ADMIN_*``). If no credential can be obtained and the
provider rejects anonymous registration, the tests skip.
"""

from urllib.parse import urlparse

import httpx
import pytest

from py_identity_model import (
    ClientDeleteRequest,
    ClientReadRequest,
    ClientRegistrationRequest,
    ClientUpdateRequest,
    delete_client,
    read_client,
    register_client,
    update_client,
)
from py_identity_model.aio.registration import (
    delete_client as aio_delete_client,
)
from py_identity_model.aio.registration import (
    read_client as aio_read_client,
)
from py_identity_model.aio.registration import (
    register_client as aio_register_client,
)
from py_identity_model.aio.registration import (
    update_client as aio_update_client,
)


HTTP_OK = 200
HTTP_CREATED = 201
REALM_PATH_MIN_PARTS = 2
REDIRECT_URIS = ["https://rp.example.com/callback"]


def _require_registration(provider_capabilities, discovery_document):
    if "registration" not in provider_capabilities:
        pytest.skip("Provider does not advertise registration_endpoint")
    if not discovery_document.registration_endpoint:
        pytest.skip("discovery missing registration_endpoint")


def _issuer_base(raw_discovery: dict) -> str:
    """Scheme://host[:port] of the OP, derived from the issuer."""
    parsed = urlparse(raw_discovery["issuer"])
    return f"{parsed.scheme}://{parsed.netloc}"


def _provider_realm(raw_discovery: dict, test_config) -> str | None:
    """The provider realm name (Keycloak issuers are ``.../realms/<realm>``)."""
    realm = test_config.get("TEST_PROVIDER_REALM")
    if realm:
        return realm
    parts = urlparse(raw_discovery["issuer"]).path.strip("/").split("/")
    if len(parts) >= REALM_PATH_MIN_PARTS and parts[0] == "realms":
        return parts[1]
    return None


def _obtain_initial_access_token(raw_discovery, test_config) -> str | None:
    """Get a client-registration initial access token, or ``None``.

    Precedence: an explicit ``TEST_REGISTRATION_INITIAL_ACCESS_TOKEN``, then a
    freshly minted token via the Keycloak admin REST API when ``TEST_ADMIN_*``
    is configured. Returns ``None`` when neither is available (the caller then
    attempts anonymous registration and skips if the provider refuses).
    """
    explicit = test_config.get("TEST_REGISTRATION_INITIAL_ACCESS_TOKEN")
    if explicit:
        return explicit

    admin_user = test_config.get("TEST_ADMIN_USERNAME")
    admin_pass = test_config.get("TEST_ADMIN_PASSWORD")
    admin_realm = test_config.get("TEST_ADMIN_REALM", "master")
    provider_realm = _provider_realm(raw_discovery, test_config)
    if not admin_user or not admin_pass or not provider_realm:
        return None

    base = _issuer_base(raw_discovery)
    with httpx.Client(timeout=10.0) as client:
        token_resp = client.post(
            f"{base}/realms/{admin_realm}/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": admin_user,
                "password": admin_pass,
            },
        )
        if token_resp.status_code != HTTP_OK:
            return None
        admin_token = token_resp.json().get("access_token")
        if not admin_token:
            return None

        iat_resp = client.post(
            f"{base}/admin/realms/{provider_realm}/clients-initial-access",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"count": 1, "expiration": 300},
        )
        if iat_resp.status_code not in (HTTP_OK, HTTP_CREATED):
            return None
        return iat_resp.json().get("token")


def _register(discovery_document, raw_discovery, test_config, client_name):
    """Register a client, skipping if the provider refuses the request."""
    initial_access_token = _obtain_initial_access_token(raw_discovery, test_config)
    response = register_client(
        ClientRegistrationRequest(
            address=discovery_document.registration_endpoint,
            redirect_uris=REDIRECT_URIS,
            client_name=client_name,
            token_endpoint_auth_method="client_secret_basic",
            initial_access_token=initial_access_token,
        )
    )
    if not response.is_successful:
        pytest.skip(f"Provider rejected dynamic registration: {response.error}")
    return response


@pytest.mark.integration
class TestDynamicRegistrationLifecycle:
    """Full RFC 7591/7592 register -> read -> update -> delete round-trip."""

    def test_register_read_update_delete(
        self,
        provider_capabilities,
        discovery_document,
        raw_discovery,
        test_config,
    ):
        """A registered client can be read, updated, then deregistered."""
        _require_registration(provider_capabilities, discovery_document)

        registered = _register(
            discovery_document, raw_discovery, test_config, "kc5-crud-sync"
        )
        assert registered.client_id, "registration returned no client_id"
        # RFC 7592 management requires the token + client URI.
        mgmt_uri = registered.registration_client_uri
        token = registered.registration_access_token
        assert token, "registration returned no registration_access_token"
        assert mgmt_uri, "registration returned no registration_client_uri"

        # If any assertion below fails before the delete, the finally still
        # deregisters the client so live providers don't accumulate orphans.
        deleted_ok = False
        try:
            # Read it back (RFC 7592 §2.1) — same client_id.
            read = read_client(
                ClientReadRequest(
                    address=mgmt_uri,
                    registration_access_token=token,
                )
            )
            assert read.is_successful, f"read failed: {read.error}"
            assert read.client_id == registered.client_id
            # RFC 7592 §3: the OP MAY rotate the registration access token on
            # each management response; use the freshest one for the next
            # request (Keycloak rotates on update, so a stale token is rejected).
            token = read.registration_access_token or token

            # Update the client name (RFC 7592 §2.2) — client_id in body.
            updated = update_client(
                ClientUpdateRequest(
                    address=mgmt_uri,
                    registration_access_token=token,
                    client_id=registered.client_id,
                    redirect_uris=REDIRECT_URIS,
                    client_name="kc5-crud-sync-renamed",
                    client_secret=registered.client_secret,
                    token_endpoint_auth_method="client_secret_basic",
                )
            )
            assert updated.is_successful, f"update failed: {updated.error}"
            assert updated.client_id == registered.client_id
            if updated.metadata is not None:
                assert updated.metadata.get("client_name") == "kc5-crud-sync-renamed"
            token = updated.registration_access_token or token

            # Deregister (RFC 7592 §2.3) — 204 No Content.
            deleted = delete_client(
                ClientDeleteRequest(
                    address=mgmt_uri,
                    registration_access_token=token,
                )
            )
            assert deleted.is_successful, f"delete failed: {deleted.error}"
            deleted_ok = True

            # Reading a deregistered client fails.
            after = read_client(
                ClientReadRequest(
                    address=mgmt_uri,
                    registration_access_token=token,
                )
            )
            assert not after.is_successful, "client still readable after delete"
        finally:
            if not deleted_ok:
                delete_client(
                    ClientDeleteRequest(
                        address=mgmt_uri,
                        registration_access_token=token,
                    )
                )


@pytest.mark.integration
class TestDynamicRegistrationLifecycleAsync:
    """Async parity for the RFC 7591/7592 lifecycle."""

    @pytest.mark.asyncio
    async def test_register_read_update_delete(
        self,
        provider_capabilities,
        discovery_document,
        raw_discovery,
        test_config,
    ):
        """Async register -> read -> update -> delete mirrors the sync path."""
        _require_registration(provider_capabilities, discovery_document)

        initial_access_token = _obtain_initial_access_token(raw_discovery, test_config)
        registered = await aio_register_client(
            ClientRegistrationRequest(
                address=discovery_document.registration_endpoint,
                redirect_uris=REDIRECT_URIS,
                client_name="kc5-crud-async",
                token_endpoint_auth_method="client_secret_basic",
                initial_access_token=initial_access_token,
            )
        )
        if not registered.is_successful:
            pytest.skip(f"Provider rejected dynamic registration: {registered.error}")
        assert registered.client_id
        mgmt_uri = registered.registration_client_uri
        token = registered.registration_access_token
        assert token
        assert mgmt_uri

        deleted_ok = False
        try:
            read = await aio_read_client(
                ClientReadRequest(
                    address=mgmt_uri,
                    registration_access_token=token,
                )
            )
            assert read.is_successful, f"async read failed: {read.error}"
            assert read.client_id == registered.client_id
            # RFC 7592 §3: use the freshest rotated token for the next request.
            token = read.registration_access_token or token

            updated = await aio_update_client(
                ClientUpdateRequest(
                    address=mgmt_uri,
                    registration_access_token=token,
                    client_id=registered.client_id,
                    redirect_uris=REDIRECT_URIS,
                    client_name="kc5-crud-async-renamed",
                    client_secret=registered.client_secret,
                    token_endpoint_auth_method="client_secret_basic",
                )
            )
            assert updated.is_successful, f"async update failed: {updated.error}"
            assert updated.client_id == registered.client_id
            token = updated.registration_access_token or token

            deleted = await aio_delete_client(
                ClientDeleteRequest(
                    address=mgmt_uri,
                    registration_access_token=token,
                )
            )
            assert deleted.is_successful, f"async delete failed: {deleted.error}"
            deleted_ok = True
        finally:
            if not deleted_ok:
                await aio_delete_client(
                    ClientDeleteRequest(
                        address=mgmt_uri,
                        registration_access_token=token,
                    )
                )
