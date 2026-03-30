"""Shared fixtures for node-oidc-provider integration tests.

These fixtures handle container health checks and provide cached
discovery/JWKS/token data for tests marked with @pytest.mark.node_oidc.

The node-oidc-provider container must be running before tests start:
    docker compose -f test-fixtures/node-oidc-provider/docker-compose.yml up -d
"""

import secrets
import time
from urllib.parse import urlencode

import httpx
import pytest

from py_identity_model import (
    AuthorizationCodeTokenRequest,
    ClientCredentialsTokenRequest,
    JwksRequest,
    get_jwks,
    parse_authorize_callback_response,
    request_authorization_code_token,
    request_client_credentials_token,
    validate_authorize_callback_state,
)
from py_identity_model.core.models import DiscoveryDocumentResponse
from py_identity_model.core.parsers import (
    extract_kid_from_jwt,
    find_key_by_kid,
)
from py_identity_model.core.pkce import generate_pkce_pair


# Node OIDC provider fixture constants
NODE_OIDC_BASE_URL = "http://localhost:9010"
NODE_OIDC_DISCO_URL = f"{NODE_OIDC_BASE_URL}/.well-known/openid-configuration"
NODE_OIDC_ISSUER = NODE_OIDC_BASE_URL

# Client credentials
CC_CLIENT_ID = "test-client-credentials"
CC_CLIENT_SECRET = "test-client-credentials-secret"

AUTH_CODE_CLIENT_ID = "test-auth-code"
AUTH_CODE_CLIENT_SECRET = "test-auth-code-secret"
AUTH_CODE_REDIRECT_URI = "http://localhost:8080/callback"

PKCE_PUBLIC_CLIENT_ID = "test-pkce-public"
PKCE_PUBLIC_REDIRECT_URI = "http://localhost:8080/callback"

# Redirect loop protection
MAX_REDIRECTS = 20


def _wait_for_provider(base_url: str, timeout: float = 30.0) -> None:
    """Wait for the node-oidc-provider to become healthy."""
    deadline = time.monotonic() + timeout
    disco_url = f"{base_url}/.well-known/openid-configuration"
    while time.monotonic() < deadline:
        try:
            resp = httpx.get(disco_url, timeout=2.0)
            if resp.status_code == 200:
                return
        except httpx.TransportError:
            pass
        time.sleep(0.5)
    pytest.fail(
        f"node-oidc-provider at {base_url} did not become healthy "
        f"within {timeout}s"
    )


def is_redirect(status_code: int) -> bool:
    return status_code in (301, 302, 303, 307, 308)


def _resolve_location(resp: httpx.Response) -> str | None:
    """Extract and resolve the Location header from a redirect response."""
    location = resp.headers.get("location")
    if location is None:
        return None
    if not location.startswith("http"):
        if location.startswith("//"):
            location = "http:" + location
        else:
            location = f"{NODE_OIDC_BASE_URL}{location}"
    return location


def _matches_redirect_uri(location: str, redirect_uri: str) -> bool:
    """Check if location matches the redirect_uri (exact or with query/fragment)."""
    return location == redirect_uri or location.startswith(
        (redirect_uri + "?", redirect_uri + "#")
    )


def perform_auth_code_flow(
    discovery: DiscoveryDocumentResponse,
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

    assert discovery.authorization_endpoint, (
        "Missing authorization_endpoint in discovery"
    )

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
        redirects = 0
        while is_redirect(resp.status_code):
            location = _resolve_location(resp)
            if location is None:
                pytest.fail(f"Redirect without Location header at {resp.url}")
            if _matches_redirect_uri(location, redirect_uri):
                break
            redirects += 1
            if redirects > MAX_REDIRECTS:
                pytest.fail(f"Too many redirects (>{MAX_REDIRECTS})")
            resp = client.get(location)

        if resp.status_code >= 400:
            pytest.fail(
                f"Auth request failed: {resp.status_code} at {resp.url}"
            )

        # Step 2: POST login to the interaction URL (devInteractions form)
        interaction_url = str(resp.url)
        resp = client.post(
            interaction_url,
            data={
                "prompt": "login",
                "login": "test-user",
                "password": "test",
            },
        )

        # Step 3: Follow redirects — may reach callback or consent page
        callback_url, resp = follow_redirects_to_callback(
            client, resp, redirect_uri
        )

        if callback_url is None:
            # Consent step: POST to the consent interaction URL
            consent_url = str(resp.url)
            if "/interaction/" in consent_url:
                resp = client.post(consent_url, data={"prompt": "consent"})
                callback_url, resp = follow_redirects_to_callback(
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
    assert discovery.token_endpoint is not None
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


def follow_redirects_to_callback(
    client: httpx.Client,
    resp: httpx.Response,
    redirect_uri: str,
) -> tuple[str | None, httpx.Response]:
    """Follow redirects until we reach the redirect_uri or run out of redirects.

    Returns (callback_url, final_response) where callback_url is None if
    we stopped at a non-redirect page (e.g. consent interaction).
    """
    redirects = 0
    while is_redirect(resp.status_code):
        location = _resolve_location(resp)
        if location is None:
            return None, resp

        if _matches_redirect_uri(location, redirect_uri):
            return location, resp

        redirects += 1
        if redirects > MAX_REDIRECTS:
            pytest.fail(f"Too many redirects (>{MAX_REDIRECTS})")

        resp = client.get(location)

    return None, resp


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
    """Fetch and cache the discovery document from node-oidc-provider.

    Uses raw httpx to bypass the library's HTTPS issuer validation,
    since the local test fixture runs on plain HTTP.
    """
    resp = httpx.get(NODE_OIDC_DISCO_URL, timeout=10.0)
    if resp.status_code != 200:
        pytest.fail(
            f"Failed to fetch node-oidc discovery: HTTP {resp.status_code}"
        )
    try:
        data = resp.json()
    except ValueError:
        pytest.fail(f"Discovery returned non-JSON: {resp.text[:200]}")
    return DiscoveryDocumentResponse(
        is_successful=True,
        issuer=data.get("issuer"),
        jwks_uri=data.get("jwks_uri"),
        authorization_endpoint=data.get("authorization_endpoint"),
        token_endpoint=data.get("token_endpoint"),
        response_types_supported=data.get("response_types_supported"),
        subject_types_supported=data.get("subject_types_supported"),
        id_token_signing_alg_values_supported=data.get(
            "id_token_signing_alg_values_supported"
        ),
        userinfo_endpoint=data.get("userinfo_endpoint"),
        registration_endpoint=data.get("registration_endpoint"),
        introspection_endpoint=data.get("introspection_endpoint"),
        scopes_supported=data.get("scopes_supported"),
        response_modes_supported=data.get("response_modes_supported"),
        grant_types_supported=data.get("grant_types_supported"),
    )


@pytest.fixture(scope="session")
def node_oidc_jwks(node_oidc_discovery):
    """Fetch and cache JWKS from node-oidc-provider."""
    response = get_jwks(JwksRequest(address=node_oidc_discovery.jwks_uri))
    if not response.is_successful:
        pytest.fail(f"Failed to fetch node-oidc JWKS: {response.error}")
    return response


@pytest.fixture(scope="session")
def node_oidc_jwt_key(node_oidc_jwks, node_oidc_cc_jwt_token):
    """Extract the signing key+algorithm for a JWT from the JWKS.

    Returns (key_dict, algorithm) for use with perform_disco=False validation.
    """
    jwt_token = node_oidc_cc_jwt_token["access_token"]
    kid = extract_kid_from_jwt(jwt_token)
    result = find_key_by_kid(kid, node_oidc_jwks.keys or [])
    assert result is not None, f"Key {kid} not found in JWKS"
    return result


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
