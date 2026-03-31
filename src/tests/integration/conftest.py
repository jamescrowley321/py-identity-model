"""Shared fixtures for integration tests.

Includes:
- Generic provider fixtures with retry/caching logic
- Discovery-driven capability detection (RFC 8414)
- Auth code flow helpers for providers with devInteractions
"""

from contextlib import suppress
from dataclasses import dataclass
import secrets
from types import MappingProxyType
from urllib.parse import urlencode, urlparse

from filelock import FileLock
import httpx
import pytest
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

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
from py_identity_model.core.discovery_policy import DiscoveryPolicy
from py_identity_model.core.models import DiscoveryDocumentResponse
from py_identity_model.core.parsers import (
    extract_kid_from_jwt,
    find_key_by_kid,
)
from py_identity_model.core.pkce import generate_pkce_pair
from py_identity_model.exceptions import TokenValidationException
from py_identity_model.sync.http_client import close_http_client

from .test_utils import get_config


# HTTP status codes
HTTP_OK = 200
HTTP_BAD_REQUEST = 400
HTTP_TOO_MANY_REQUESTS = 429

# JWT format: three dot-separated segments
JWT_SEGMENT_SEPARATOR_COUNT = 2


# ============================================================================
# Generic provider fixtures
# ============================================================================

RATE_LIMIT_ERROR_MESSAGE = "Rate limited"
MAX_REDIRECTS = 20


def retry_with_backoff():
    """Retry decorator that handles HTTP 429 rate limiting."""
    return retry(
        retry=retry_if_exception_type(httpx.HTTPStatusError),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        stop=stop_after_attempt(3),
        reraise=True,
    )


@pytest.fixture(scope="session")
def test_config(env_file, tmp_path_factory):
    """Session-scoped test configuration with file-lock for xdist safety."""
    root_tmp_dir = tmp_path_factory.getbasetemp().parent
    lock_file = root_tmp_dir / "test_config.lock"
    with FileLock(str(lock_file)):
        return get_config(env_file)


@pytest.fixture(scope="session")
def discovery_document(test_config):
    """Cached discovery document with retry logic for rate limits."""

    @retry_with_backoff()
    def fetch_discovery():
        require_https = test_config.get("TEST_REQUIRE_HTTPS", True)
        policy = DiscoveryPolicy(require_https=require_https)
        disco_doc_req = DiscoveryDocumentRequest(
            address=test_config["TEST_DISCO_ADDRESS"],
            policy=policy,
        )
        response = get_discovery_document(disco_doc_req)

        if not response.is_successful and "429" in str(response.error):
            request = httpx.Request("GET", test_config["TEST_DISCO_ADDRESS"])
            raise httpx.HTTPStatusError(
                RATE_LIMIT_ERROR_MESSAGE,
                request=request,
                response=httpx.Response(429),
            )

        return response

    response = fetch_discovery()
    if not response.is_successful:
        pytest.fail(f"Failed to fetch discovery document: {response.error}")
    return response


@pytest.fixture(scope="session")
def raw_discovery(test_config):
    """Raw discovery JSON for capability detection.

    Provides access to all RFC 8414 fields, including those not yet
    in the typed DiscoveryDocumentResponse model. Uses retry logic
    for rate-limited providers (consistent with discovery_document).
    """
    address = test_config["TEST_DISCO_ADDRESS"]

    @retry_with_backoff()
    def fetch_raw():
        resp = httpx.get(address, timeout=10.0)
        if resp.status_code == HTTP_TOO_MANY_REQUESTS:
            raise httpx.HTTPStatusError(
                RATE_LIMIT_ERROR_MESSAGE,
                request=resp.request,
                response=resp,
            )
        return resp

    try:
        resp = fetch_raw()
    except httpx.TransportError as exc:
        pytest.fail(f"raw_discovery: cannot reach {address}: {exc}")
    if resp.status_code != HTTP_OK:
        pytest.fail(f"raw_discovery: HTTP {resp.status_code} from {address}")
    try:
        return resp.json()
    except ValueError as exc:
        pytest.fail(f"raw_discovery: invalid JSON from {address}: {exc}")


def _detect_grant_capabilities(raw_discovery: dict, grants: set) -> set[str]:
    """Detect grant type and endpoint capabilities."""
    caps = set()
    if raw_discovery.get("authorization_endpoint"):
        caps.add("authorization_code")
    if "client_credentials" in grants:
        caps.add("client_credentials")
    if "refresh_token" in grants:
        caps.add("refresh_token")
    if "urn:ietf:params:oauth:grant-type:device_code" in grants:
        caps.add("device_authorization")
    if "urn:ietf:params:oauth:grant-type:token-exchange" in grants:
        caps.add("token_exchange")
    for endpoint, cap in (
        ("introspection_endpoint", "introspection"),
        ("revocation_endpoint", "revocation"),
        ("userinfo_endpoint", "userinfo"),
        ("device_authorization_endpoint", "device_authorization_endpoint"),
        ("pushed_authorization_request_endpoint", "par"),
    ):
        if raw_discovery.get(endpoint):
            caps.add(cap)
    return caps


def _detect_feature_capabilities(raw_discovery: dict) -> set[str]:
    """Detect feature capabilities from discovery metadata."""
    caps = set()
    challenge_methods = raw_discovery.get("code_challenge_methods_supported", [])
    if "S256" in challenge_methods:
        caps.add("pkce")
    if raw_discovery.get("dpop_signing_alg_values_supported"):
        caps.add("dpop")
    if raw_discovery.get("request_parameter_supported"):
        caps.add("jar")

    # devInteractions: only local fixtures support automated
    # browser-like auth code flows
    issuer = raw_discovery.get("issuer", "")
    if issuer.startswith(("http://localhost", "http://127.0.0.1")):
        caps.add("dev_interactions")

    return caps


@pytest.fixture(scope="session")
def provider_capabilities(raw_discovery):
    """Detect provider capabilities from discovery document (RFC 8414).

    Capabilities are derived entirely from the discovery document —
    no TEST_PROVIDER env var needed.
    """
    grants = set(raw_discovery.get("grant_types_supported", []))
    caps = _detect_grant_capabilities(raw_discovery, grants)
    caps |= _detect_feature_capabilities(raw_discovery)
    return caps


@pytest.fixture(scope="session")
def jwks_response(test_config):
    """Cached JWKS response with retry logic for rate limits."""

    @retry_with_backoff()
    def fetch_jwks():
        jwks_req = JwksRequest(address=test_config["TEST_JWKS_ADDRESS"])
        response = get_jwks(jwks_req)

        if not response.is_successful and "429" in str(response.error):
            request = httpx.Request("GET", test_config["TEST_JWKS_ADDRESS"])
            raise httpx.HTTPStatusError(
                RATE_LIMIT_ERROR_MESSAGE,
                request=request,
                response=httpx.Response(429),
            )

        return response

    response = fetch_jwks()
    if not response.is_successful:
        pytest.fail(f"Failed to fetch JWKS: {response.error}")
    return response


@pytest.fixture(scope="session")
def token_endpoint(discovery_document):
    """Provide the token endpoint from cached discovery document."""
    return discovery_document.token_endpoint


@pytest.fixture(scope="session")
def jwks_uri(discovery_document):
    """Provide the JWKS URI from cached discovery document."""
    return discovery_document.jwks_uri


@pytest.fixture(scope="session")
def issuer(discovery_document):
    """Provide the issuer from cached discovery document."""
    return discovery_document.issuer


@pytest.fixture(scope="session")
def userinfo_endpoint(discovery_document):
    """Provide the UserInfo endpoint from cached discovery document."""
    return discovery_document.userinfo_endpoint


@pytest.fixture(scope="session")
def require_https(test_config):
    """Provide whether HTTPS is required for the current provider."""
    return test_config.get("TEST_REQUIRE_HTTPS", True)


@pytest.fixture(scope="session")
def client_credentials_token(test_config, token_endpoint):
    """Cached client credentials token with retry logic for rate limits."""

    @retry_with_backoff()
    def fetch_token():
        response = request_client_credentials_token(
            ClientCredentialsTokenRequest(
                client_id=test_config["TEST_CLIENT_ID"],
                client_secret=test_config["TEST_CLIENT_SECRET"],
                address=token_endpoint,
                scope=test_config["TEST_SCOPE"],
            )
        )

        if not response.is_successful and "429" in str(response.error):
            request = httpx.Request("POST", token_endpoint)
            raise httpx.HTTPStatusError(
                RATE_LIMIT_ERROR_MESSAGE,
                request=request,
                response=httpx.Response(429),
            )

        return response

    response = fetch_token()
    if not response.is_successful:
        pytest.fail(f"Failed to obtain token: {response.error}")
    return response


@pytest.fixture(scope="session")
def jwt_access_token(client_credentials_token, test_config, token_endpoint):
    """JWT-format access token for manual key validation tests.

    Uses the standard client_credentials token if it's already a JWT.
    Falls back to requesting with resource param for providers that
    need it for JWT format (e.g., node-oidc without defaultResource).
    Skips if no JWT token can be obtained.
    """
    # Check if standard token is already JWT
    token = client_credentials_token.token
    access_token = token.get("access_token", "")
    if access_token.count(".") == JWT_SEGMENT_SEPARATOR_COUNT:
        return token

    # Fallback: request with resource param to force JWT format
    @retry_with_backoff()
    def fetch_jwt_with_resource():
        r = httpx.post(
            token_endpoint,
            data={
                "grant_type": "client_credentials",
                "scope": test_config.get("TEST_SCOPE", "openid"),
                "resource": "urn:test:api",
            },
            auth=(
                test_config["TEST_CLIENT_ID"],
                test_config["TEST_CLIENT_SECRET"],
            ),
            timeout=10.0,
        )
        if r.status_code == HTTP_TOO_MANY_REQUESTS:
            raise httpx.HTTPStatusError(
                RATE_LIMIT_ERROR_MESSAGE,
                request=r.request,
                response=r,
            )
        return r

    resp = fetch_jwt_with_resource()
    if resp.status_code == HTTP_OK:
        data = resp.json()
        if data.get("access_token", "").count(".") == JWT_SEGMENT_SEPARATOR_COUNT:
            return data

    pytest.skip("Provider does not return JWT-format access tokens")


@pytest.fixture(scope="session")
def jwt_signing_key(jwks_response, jwt_access_token):
    """Extract the signing key and algorithm for a JWT from JWKS."""
    jwt_token = jwt_access_token["access_token"]
    kid = extract_kid_from_jwt(jwt_token)
    try:
        return find_key_by_kid(kid, jwks_response.keys or [])
    except TokenValidationException:
        pytest.skip(f"Key {kid} not found in JWKS")


@pytest.fixture(scope="session")
def opaque_access_token(test_config, token_endpoint):
    """Opaque access token for introspection/revocation tests.

    Some providers (e.g. node-oidc-provider) cannot introspect or revoke
    JWT-format tokens.  This fixture uses a dedicated client that receives
    opaque tokens.  Skips when the opaque client is not configured.
    """
    opaque_id = test_config.get("TEST_OPAQUE_CLIENT_ID")
    opaque_secret = test_config.get("TEST_OPAQUE_CLIENT_SECRET")
    if not opaque_id or not opaque_secret:
        pytest.skip("TEST_OPAQUE_CLIENT_ID not configured")

    @retry_with_backoff()
    def fetch_token():
        response = request_client_credentials_token(
            ClientCredentialsTokenRequest(
                client_id=opaque_id,
                client_secret=opaque_secret,
                address=token_endpoint,
                scope=test_config["TEST_SCOPE"],
            )
        )
        if not response.is_successful and "429" in str(response.error):
            request = httpx.Request("POST", token_endpoint)
            raise httpx.HTTPStatusError(
                RATE_LIMIT_ERROR_MESSAGE,
                request=request,
                response=httpx.Response(429),
            )
        return response

    response = fetch_token()
    if not response.is_successful:
        pytest.fail(f"Failed to obtain opaque token: {response.error}")
    assert response.token is not None, "Token response has no token dict"
    return response.token["access_token"]


@pytest.fixture(scope="session", autouse=True)
def cleanup_http_client():
    """Close the persistent HTTP client after all tests complete."""
    yield
    with suppress(Exception):
        close_http_client()


# ============================================================================
# Auth code flow helpers (capability-gated)
# ============================================================================


def _resolve_location(resp: httpx.Response) -> str | None:
    """Extract and resolve the Location header from a redirect.

    Handles absolute URLs, protocol-relative (//), absolute paths (/),
    and bare relative paths per RFC 7231 section 7.1.2.
    """
    location = resp.headers.get("location")
    if location is None:
        return None
    if not location.startswith("http"):
        parsed = urlparse(str(resp.url))
        base = f"{parsed.scheme}://{parsed.netloc}"
        if location.startswith("//"):
            location = f"{parsed.scheme}:{location}"
        elif location.startswith("/"):
            location = f"{base}{location}"
        else:
            # Bare relative path (no leading slash) — resolve
            # against the current URL's directory
            parent = parsed.path.rsplit("/", 1)[0]
            location = f"{base}{parent}/{location}"
    return location


def is_redirect(status_code: int) -> bool:
    return status_code in (301, 302, 303, 307, 308)


def _matches_redirect_uri(location: str, redirect_uri: str) -> bool:
    """Check if location matches the redirect_uri."""
    return location == redirect_uri or location.startswith(
        (redirect_uri + "?", redirect_uri + "#")
    )


def follow_redirects_to_callback(
    client: httpx.Client,
    resp: httpx.Response,
    redirect_uri: str,
) -> tuple[str | None, httpx.Response]:
    """Follow redirects until we reach the redirect_uri."""
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


def _follow_redirects_counted(
    client: httpx.Client,
    resp: httpx.Response,
    redirect_uri: str,
    prior_redirects: int,
) -> tuple[str | None, httpx.Response]:
    """Follow redirects with a shared counter across the flow."""
    total = prior_redirects
    while is_redirect(resp.status_code):
        location = _resolve_location(resp)
        if location is None:
            return None, resp

        if _matches_redirect_uri(location, redirect_uri):
            return location, resp

        total += 1
        if total > MAX_REDIRECTS:
            pytest.fail(f"Too many redirects (>{MAX_REDIRECTS})")

        resp = client.get(location)

    return None, resp


@dataclass(frozen=True)
class AuthCodeFlowConfig:
    """Optional configuration for :func:`perform_auth_code_flow`."""

    client_secret: str | None = None
    scope: str = "openid profile email offline_access"
    resource: str | None = None
    login_hint: str = "test-user"
    login_password: str = "test"


def perform_auth_code_flow(
    discovery: DiscoveryDocumentResponse,
    client_id: str,
    redirect_uri: str,
    config: AuthCodeFlowConfig | None = None,
) -> MappingProxyType:
    """Perform a full auth code + PKCE flow using devInteractions.

    Args:
        discovery: Discovery document response.
        client_id: OAuth client identifier.
        redirect_uri: Registered redirect URI.
        config: Optional flow configuration (scope, credentials, etc.).
            Defaults to ``AuthCodeFlowConfig()`` when ``None``.

    Returns dict with token_response, state, callback,
    state_result, code_verifier.
    """
    if config is None:
        config = AuthCodeFlowConfig()
    code_verifier, code_challenge = generate_pkce_pair()
    state = secrets.token_urlsafe(32)

    assert discovery.authorization_endpoint, (
        "Missing authorization_endpoint in discovery"
    )

    auth_params: dict[str, str] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": config.scope,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    if config.resource:
        auth_params["resource"] = config.resource

    auth_url = f"{discovery.authorization_endpoint}?{urlencode(auth_params)}"

    # Use a single redirect counter across the entire flow
    total_redirects = 0

    with httpx.Client(follow_redirects=False, timeout=10.0) as client:
        resp = client.get(auth_url)
        while is_redirect(resp.status_code):
            location = _resolve_location(resp)
            if location is None:
                pytest.fail(f"Redirect without Location header at {resp.url}")
            if _matches_redirect_uri(location, redirect_uri):
                break
            total_redirects += 1
            if total_redirects > MAX_REDIRECTS:
                pytest.fail(f"Too many redirects (>{MAX_REDIRECTS})")
            resp = client.get(location)

        if resp.status_code >= HTTP_BAD_REQUEST:
            pytest.fail(f"Auth request failed: {resp.status_code} at {resp.url}")

        interaction_url = str(resp.url)
        resp = client.post(
            interaction_url,
            data={
                "prompt": "login",
                "login": config.login_hint,
                "password": config.login_password,
            },
        )

        callback_url, resp = _follow_redirects_counted(
            client, resp, redirect_uri, total_redirects
        )

        if callback_url is None:
            consent_url = str(resp.url)
            if "/interaction/" in consent_url:
                resp = client.post(consent_url, data={"prompt": "consent"})
                callback_url, resp = _follow_redirects_counted(
                    client, resp, redirect_uri, total_redirects
                )

        if callback_url is None:
            pytest.fail(
                "Auth code flow did not reach redirect_uri. "
                f"Last: {resp.status_code} at {resp.url}"
            )

    callback = parse_authorize_callback_response(callback_url)
    if not callback.is_successful:
        pytest.fail(f"Auth callback error: {callback.error}")

    state_result = validate_authorize_callback_state(callback, state)
    if not state_result.is_valid:
        pytest.fail(f"State validation failed: {state_result.result}")

    assert callback.code is not None
    assert discovery.token_endpoint is not None
    token_request = AuthorizationCodeTokenRequest(
        address=discovery.token_endpoint,
        client_id=client_id,
        code=callback.code,
        redirect_uri=redirect_uri,
        code_verifier=code_verifier,
        client_secret=config.client_secret,
    )
    token_response = request_authorization_code_token(token_request)

    return MappingProxyType(
        {
            "token_response": token_response,
            "state": state,
            "callback": callback,
            "state_result": state_result,
            "code_verifier": code_verifier,
        }
    )


@pytest.fixture(scope="session")
def auth_code_result(provider_capabilities, discovery_document, test_config):
    """Perform auth code + PKCE flow with confidential client.

    Skips if provider lacks dev_interactions or authorization_code.
    """
    if "dev_interactions" not in provider_capabilities:
        pytest.skip(
            "Provider does not support automated auth code flow (no devInteractions)"
        )
    if "authorization_code" not in provider_capabilities:
        pytest.skip("Provider does not advertise authorization_endpoint")

    client_id = test_config.get("TEST_AUTH_CODE_CLIENT_ID")
    redirect_uri = test_config.get("TEST_AUTH_CODE_REDIRECT_URI")
    client_secret = test_config.get("TEST_AUTH_CODE_CLIENT_SECRET")
    if not client_id or not redirect_uri:
        pytest.skip(
            "TEST_AUTH_CODE_CLIENT_ID and "
            "TEST_AUTH_CODE_REDIRECT_URI required "
            "for auth code flow tests"
        )

    return perform_auth_code_flow(
        discovery=discovery_document,
        client_id=client_id,
        redirect_uri=redirect_uri,
        config=AuthCodeFlowConfig(
            client_secret=client_secret,
            scope="openid profile email offline_access",
            resource="urn:test:api",
        ),
    )


@pytest.fixture(scope="session")
def public_auth_code_result(provider_capabilities, discovery_document, test_config):
    """Perform auth code + PKCE flow with public client.

    Skips if provider lacks dev_interactions or authorization_code.
    """
    if "dev_interactions" not in provider_capabilities:
        pytest.skip(
            "Provider does not support automated auth code flow (no devInteractions)"
        )
    if "authorization_code" not in provider_capabilities:
        pytest.skip("Provider does not advertise authorization_endpoint")

    client_id = test_config.get("TEST_PKCE_PUBLIC_CLIENT_ID")
    redirect_uri = test_config.get("TEST_PKCE_PUBLIC_REDIRECT_URI")
    if not client_id or not redirect_uri:
        pytest.skip(
            "TEST_PKCE_PUBLIC_CLIENT_ID and "
            "TEST_PKCE_PUBLIC_REDIRECT_URI required "
            "for public client auth code flow tests"
        )

    return perform_auth_code_flow(
        discovery=discovery_document,
        client_id=client_id,
        redirect_uri=redirect_uri,
        config=AuthCodeFlowConfig(
            scope="openid profile email offline_access",
            resource="urn:test:api",
        ),
    )
