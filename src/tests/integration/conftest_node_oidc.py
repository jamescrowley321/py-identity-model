"""Shared fixtures for node-oidc-provider integration tests.

These fixtures handle container health checks and provide cached
discovery/JWKS/token data for tests marked with @pytest.mark.node_oidc.

The node-oidc-provider container must be running before tests start:
    docker compose -f test-fixtures/node-oidc-provider/docker-compose.yml up -d
"""

from contextlib import suppress
import secrets
import time
from urllib.parse import urlencode

import httpx
import pytest

from py_identity_model import (
    AuthorizationCodeTokenRequest,
    ClientCredentialsTokenRequest,
    DiscoveryDocumentRequest,
    JwksRequest,
    get_discovery_document,
    get_jwks,
    parse_authorize_callback_response,
    request_authorization_code_token,
    request_client_credentials_token,
    validate_authorize_callback_state,
)
from py_identity_model.core.pkce import generate_pkce_pair
from py_identity_model.sync.http_client import close_http_client


# Node OIDC provider fixture constants
NODE_OIDC_BASE_URL = "http://localhost:9010"
NODE_OIDC_DISCO_URL = f"{NODE_OIDC_BASE_URL}/.well-known/openid-configuration"

# Client credentials
CC_CLIENT_ID = "test-client-credentials"
CC_CLIENT_SECRET = "test-client-credentials-secret"

AUTH_CODE_CLIENT_ID = "test-auth-code"
AUTH_CODE_CLIENT_SECRET = "test-auth-code-secret"
AUTH_CODE_REDIRECT_URI = "http://localhost:8080/callback"

PKCE_PUBLIC_CLIENT_ID = "test-pkce-public"
PKCE_PUBLIC_REDIRECT_URI = "http://localhost:8080/callback"


def _wait_for_provider(base_url: str, timeout: float = 30.0) -> None:
    """Wait for the node-oidc-provider to become healthy."""
    deadline = time.monotonic() + timeout
    disco_url = f"{base_url}/.well-known/openid-configuration"
    while time.monotonic() < deadline:
        try:
            resp = httpx.get(disco_url, timeout=2.0)
            if resp.status_code == 200:
                return
        except httpx.ConnectError:
            pass
        time.sleep(0.5)
    pytest.fail(
        f"node-oidc-provider at {base_url} did not become healthy "
        f"within {timeout}s"
    )


def _follow_redirect(
    client: httpx.Client, resp: httpx.Response
) -> httpx.Response:
    """Follow a single HTTP redirect, handling relative URLs."""
    location = resp.headers["location"]
    if not location.startswith("http"):
        location = f"{NODE_OIDC_BASE_URL}{location}"
    return client.get(location)


def _is_redirect(status_code: int) -> bool:
    return status_code in (301, 302, 303, 307, 308)


def perform_auth_code_flow(
    discovery,
    client_id: str,
    redirect_uri: str,
    client_secret: str | None = None,
    scope: str = "openid profile email offline_access",
    resource: str | None = None,
) -> dict:
    """Perform a full auth code + PKCE flow using devInteractions.

    Uses httpx.Client with cookies to navigate the devInteractions login.
    Returns dict with token_response, state, callback, state_result, code_verifier.
    """
    code_verifier, code_challenge = generate_pkce_pair()
    state = secrets.token_urlsafe(32)

    # Build authorization URL
    auth_params: dict[str, str] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": scope,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    if resource:
        auth_params["resource"] = resource

    auth_url = f"{discovery.authorization_endpoint}?{urlencode(auth_params)}"

    with httpx.Client(follow_redirects=False, timeout=10.0) as client:
        # Step 1: GET authorization URL → redirects to interaction
        resp = client.get(auth_url)
        while _is_redirect(resp.status_code):
            location = resp.headers["location"]
            if not location.startswith("http"):
                location = f"{NODE_OIDC_BASE_URL}{location}"
            # Don't follow redirect to our redirect_uri
            if location.startswith(redirect_uri):
                break
            resp = client.get(location)

        # Step 2: POST login to the interaction
        interaction_url = str(resp.url)
        login_url = f"{interaction_url}/login"
        resp = client.post(
            login_url,
            data={"login": "test-user", "password": "test"},
        )

        # Step 3: Follow redirects through consent and back to redirect_uri
        callback_url = _follow_redirects_to_callback(
            client, resp, redirect_uri
        )

        if callback_url is None:
            # May need to confirm consent
            current_url = str(resp.url)
            if "/interaction/" in current_url:
                confirm_url = f"{current_url}/confirm"
                resp = client.post(confirm_url)
                callback_url = _follow_redirects_to_callback(
                    client, resp, redirect_uri
                )

        if callback_url is None:
            pytest.fail(
                f"Auth code flow did not reach redirect_uri. "
                f"Last: {resp.status_code} at {resp.url}"
            )

    # Parse callback and validate state
    callback = parse_authorize_callback_response(callback_url)
    if not callback.is_successful:
        pytest.fail(f"Auth callback error: {callback.error}")

    state_result = validate_authorize_callback_state(callback, state)
    if not state_result.is_valid:
        pytest.fail(f"State validation failed: {state_result.result}")

    # Exchange code for tokens
    assert callback.code is not None
    token_request = AuthorizationCodeTokenRequest(
        address=discovery.token_endpoint,
        client_id=client_id,
        code=callback.code,
        redirect_uri=redirect_uri,
        code_verifier=code_verifier,
        client_secret=client_secret,
    )
    token_response = request_authorization_code_token(token_request)

    return {
        "token_response": token_response,
        "state": state,
        "callback": callback,
        "state_result": state_result,
        "code_verifier": code_verifier,
    }


def _follow_redirects_to_callback(
    client: httpx.Client,
    resp: httpx.Response,
    redirect_uri: str,
) -> str | None:
    """Follow redirects until we reach the redirect_uri or run out of redirects."""
    while _is_redirect(resp.status_code):
        location = resp.headers["location"]
        if not location.startswith("http"):
            location = f"{NODE_OIDC_BASE_URL}{location}"

        if location.startswith(redirect_uri):
            return location

        resp = client.get(location)

    return None


# ============================================================================
# Session-scoped fixtures
# ============================================================================


@pytest.fixture(scope="session")
def node_oidc_provider():
    """Ensure the node-oidc-provider container is running and healthy."""
    _wait_for_provider(NODE_OIDC_BASE_URL)
    return NODE_OIDC_BASE_URL


@pytest.fixture(scope="session")
def node_oidc_discovery(node_oidc_provider):
    """Fetch and cache the discovery document from node-oidc-provider."""
    response = get_discovery_document(
        DiscoveryDocumentRequest(address=NODE_OIDC_DISCO_URL)
    )
    if not response.is_successful:
        pytest.fail(f"Failed to fetch node-oidc discovery: {response.error}")
    return response


@pytest.fixture(scope="session")
def node_oidc_jwks(node_oidc_discovery):
    """Fetch and cache JWKS from node-oidc-provider."""
    response = get_jwks(JwksRequest(address=node_oidc_discovery.jwks_uri))
    if not response.is_successful:
        pytest.fail(f"Failed to fetch node-oidc JWKS: {response.error}")
    return response


@pytest.fixture(scope="session")
def node_oidc_cc_jwt_token(node_oidc_provider, node_oidc_discovery):
    """Get a JWT client_credentials token (with resource=urn:test:api).

    Uses raw httpx because ClientCredentialsTokenRequest does not support
    the ``resource`` parameter needed for JWT access tokens.
    """
    resp = httpx.post(
        node_oidc_discovery.token_endpoint,
        data={
            "grant_type": "client_credentials",
            "scope": "openid api",
            "resource": "urn:test:api",
        },
        auth=(CC_CLIENT_ID, CC_CLIENT_SECRET),
        timeout=10.0,
    )
    if resp.status_code != 200:
        pytest.fail(f"Failed to get JWT client_credentials token: {resp.text}")
    return resp.json()


@pytest.fixture(scope="session")
def node_oidc_cc_opaque_token(node_oidc_provider, node_oidc_discovery):
    """Get an opaque client_credentials token (no resource param)."""
    response = request_client_credentials_token(
        ClientCredentialsTokenRequest(
            address=node_oidc_discovery.token_endpoint,
            client_id=CC_CLIENT_ID,
            client_secret=CC_CLIENT_SECRET,
            scope="openid api",
        )
    )
    if not response.is_successful:
        pytest.fail(
            f"Failed to get opaque client_credentials token: {response.error}"
        )
    return response


@pytest.fixture(scope="session")
def node_oidc_auth_code_result(node_oidc_provider, node_oidc_discovery):
    """Perform auth code + PKCE flow with confidential client.

    Returns dict with token_response, state, callback, state_result, code_verifier.
    """
    return perform_auth_code_flow(
        discovery=node_oidc_discovery,
        client_id=AUTH_CODE_CLIENT_ID,
        redirect_uri=AUTH_CODE_REDIRECT_URI,
        client_secret=AUTH_CODE_CLIENT_SECRET,
        scope="openid profile email offline_access",
        resource="urn:test:api",
    )


@pytest.fixture(scope="session")
def node_oidc_public_auth_code_result(node_oidc_provider, node_oidc_discovery):
    """Perform auth code + PKCE flow with public client (no client_secret)."""
    return perform_auth_code_flow(
        discovery=node_oidc_discovery,
        client_id=PKCE_PUBLIC_CLIENT_ID,
        redirect_uri=PKCE_PUBLIC_REDIRECT_URI,
        scope="openid profile email offline_access",
        resource="urn:test:api",
    )


@pytest.fixture(scope="session", autouse=True)
def _cleanup_node_oidc_http_client():
    """Ensure HTTP client is closed after node-oidc tests."""
    yield
    with suppress(Exception):
        close_http_client()
