"""OIDC RP conformance test harness.

Thin FastAPI application that acts as an OpenID Connect Relying Party,
using py-identity-model's public API to exercise all RP conformance tests.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import logging
import os
import secrets
from urllib.parse import urlencode

from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.concurrency import run_in_threadpool

from py_identity_model import (
    AuthorizationCodeTokenRequest,
    DiscoveryDocumentRequest,
    DiscoveryPolicy,
    HTTPClient,
    TokenValidationConfig,
    UserInfoRequest,
    build_authorization_url,
    generate_pkce_pair,
    get_discovery_document,
    get_userinfo,
    parse_authorize_callback_response,
    parse_discovery_url,
    request_authorization_code_token,
    validate_authorize_callback_state,
    validate_token,
)
from py_identity_model.exceptions import (
    ConfigurationException,
    PyIdentityModelException,
    TokenValidationException,
)


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("conformance-rp")

app = FastAPI(title="py-identity-model Conformance RP")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SUITE_BASE_URL = os.environ.get(
    "CONFORMANCE_SUITE_BASE_URL", "https://localhost.emobix.co.uk:8443"
)
RP_BASE_URL = os.environ.get("RP_BASE_URL", "http://localhost:8888")

# ---------------------------------------------------------------------------
# Session store — in-memory, keyed by state parameter
# ---------------------------------------------------------------------------


@dataclass
class AuthSession:
    """Tracks per-flow state between /authorize and /callback."""

    issuer: str
    state: str
    nonce: str
    code_verifier: str | None = None
    client_id: str = ""
    client_secret: str = ""
    redirect_uri: str = ""
    skip_userinfo: bool = False
    # Results populated after callback
    result: dict = field(default_factory=dict)


# state -> AuthSession
sessions: dict[str, AuthSession] = {}

# test_id -> AuthSession (for the runner to retrieve results)
test_results: dict[str, AuthSession] = {}

# Shared HTTP client that skips TLS verification (conformance suite uses self-signed certs)
_http_client: HTTPClient | None = None


def _get_http_client() -> HTTPClient:
    global _http_client
    if _http_client is None:
        _http_client = HTTPClient(verify=False)
    return _http_client


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/")
@app.get("/health")
def health() -> dict:
    """Health check."""
    return {"status": "ok", "service": "conformance-rp"}


@app.get("/discover", response_model=None)
def discover(
    issuer: str = Query(..., description="Issuer URL for this test"),
    test_id: str = Query("", description="Test module ID for result tracking"),
) -> JSONResponse:
    """Fetch discovery document (and JWKS) without starting an auth flow.

    Used for Config RP discovery-only tests where the suite just needs to
    observe the RP fetching the openid-configuration endpoint.
    """
    http_client = _get_http_client()
    try:
        disco_endpoint = parse_discovery_url(issuer)
    except ConfigurationException as exc:
        error_msg = f"invalid_issuer: {exc}"
        logger.error("Discovery URL parse error: %s", exc)
        if test_id:
            error_session = AuthSession(issuer=issuer, state="", nonce="")
            error_session.result = {
                "test_id": test_id,
                "status": "error",
                "error": error_msg,
            }
            test_results[test_id] = error_session
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_issuer", "detail": str(exc)},
        )
    policy = DiscoveryPolicy(require_https=False, validate_issuer=True)
    disco = get_discovery_document(
        DiscoveryDocumentRequest(address=disco_endpoint.url, policy=policy),
        http_client=http_client,
    )

    if not disco.is_successful:
        if test_id:
            error_session = AuthSession(issuer=issuer, state="", nonce="")
            error_session.result = {
                "test_id": test_id,
                "status": "error",
                "error": f"discovery_failed: {disco.error}",
            }
            test_results[test_id] = error_session
        return JSONResponse(
            status_code=502,
            content={"error": "discovery_failed", "detail": disco.error},
        )

    if test_id:
        session = AuthSession(issuer=issuer, state="", nonce="")
        session.result = {
            "test_id": test_id,
            "status": "success",
            "issuer": disco.issuer,
        }
        test_results[test_id] = session

    return JSONResponse(content={"status": "ok", "issuer": disco.issuer})


@app.get("/authorize", response_model=None)
def authorize(
    issuer: str = Query(..., description="Issuer URL for this test"),
    client_id: str = Query(..., description="Client ID registered with the suite"),
    client_secret: str = Query("", description="Client secret"),
    test_id: str = Query("", description="Test module ID for result tracking"),
    use_pkce: str = Query("false", description="Whether to use PKCE"),
    skip_userinfo: str = Query(
        "false", description="Skip UserInfo fetch after token validation"
    ),
    scope: str = Query(
        "openid profile email address phone", description="Requested scopes"
    ),
) -> RedirectResponse | JSONResponse:
    """Build an authorization URL and redirect to the OP.

    The conformance test runner calls this to start an authorization flow.
    """
    http_client = _get_http_client()

    # Fetch discovery document for this issuer
    try:
        disco_endpoint = parse_discovery_url(issuer)
    except ConfigurationException as exc:
        error_msg = f"invalid_issuer: {exc}"
        logger.error("Discovery URL parse error: %s", exc)
        if test_id:
            error_session = AuthSession(issuer=issuer, state="", nonce="")
            error_session.result = {
                "test_id": test_id,
                "status": "error",
                "error": error_msg,
            }
            test_results[test_id] = error_session
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_issuer", "detail": str(exc)},
        )
    policy = DiscoveryPolicy(require_https=False, validate_issuer=True)
    disco = get_discovery_document(
        DiscoveryDocumentRequest(address=disco_endpoint.url, policy=policy),
        http_client=http_client,
    )

    if not disco.is_successful:
        # Discovery failure includes format/validation errors — store as test result
        if test_id:
            error_session = AuthSession(issuer=issuer, state="", nonce="")
            error_session.result = {
                "test_id": test_id,
                "status": "error",
                "error": f"discovery_failed: {disco.error}",
            }
            test_results[test_id] = error_session
        return JSONResponse(
            status_code=502,
            content={"error": "discovery_failed", "detail": disco.error},
        )

    # OIDC Discovery 1.0 §4.3: issuer in document MUST match the URL used to retrieve it
    if not disco.issuer:
        error_msg = "Discovery document missing required 'issuer' field"
        logger.error(error_msg)
        if test_id:
            error_session = AuthSession(issuer=issuer, state="", nonce="")
            error_session.result = {
                "test_id": test_id,
                "status": "error",
                "error": f"missing_issuer: {error_msg}",
            }
            test_results[test_id] = error_session
        return JSONResponse(
            status_code=502,
            content={"error": "missing_issuer", "detail": error_msg},
        )
    if disco.issuer != issuer:
        error_msg = (
            f"Issuer mismatch: discovery document issuer '{disco.issuer}' "
            f"does not match expected '{issuer}'"
        )
        logger.error(error_msg)
        if test_id:
            error_session = AuthSession(issuer=issuer, state="", nonce="")
            error_session.result = {
                "test_id": test_id,
                "status": "error",
                "error": f"issuer_mismatch: {error_msg}",
            }
            test_results[test_id] = error_session
        return JSONResponse(
            status_code=502,
            content={"error": "issuer_mismatch", "detail": error_msg},
        )

    # Generate per-flow state and nonce
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)

    redirect_uri = f"{RP_BASE_URL}/callback"

    # Optional PKCE
    code_verifier: str | None = None
    code_challenge: str | None = None
    code_challenge_method: str | None = None
    if use_pkce.lower() == "true":
        code_verifier, code_challenge = generate_pkce_pair()
        code_challenge_method = "S256"

    # Build the authorization URL
    if disco.authorization_endpoint is None:
        return JSONResponse(
            status_code=502,
            content={
                "error": "missing_endpoint",
                "detail": "Discovery document missing authorization_endpoint",
            },
        )
    auth_url = build_authorization_url(
        authorization_endpoint=disco.authorization_endpoint,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        response_type="code",
        state=state,
        nonce=nonce,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
    )

    # Store session
    session = AuthSession(
        issuer=issuer,
        state=state,
        nonce=nonce,
        code_verifier=code_verifier,
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
        skip_userinfo=skip_userinfo.lower() == "true",
    )
    sessions[state] = session
    if test_id:
        session.result["test_id"] = test_id

    logger.info("Redirecting to OP: %s", auth_url)
    return RedirectResponse(url=auth_url, status_code=302)


def _fetch_and_validate_discovery(
    issuer: str, http_client: HTTPClient, session: AuthSession
) -> HTMLResponse | tuple:
    """Fetch discovery document and validate issuer for a callback flow.

    Returns an HTMLResponse on error, or a (disco, disco_endpoint) tuple on success.
    """
    try:
        disco_endpoint = parse_discovery_url(issuer)
    except ConfigurationException as exc:
        error_msg = f"invalid_issuer: {exc}"
        logger.error("Discovery URL parse error in callback: %s", exc)
        session.result["status"] = "error"
        session.result["error"] = error_msg
        _store_test_result(session)
        return HTMLResponse(
            content=f"<h1>Invalid Issuer</h1><p>{exc}</p>",
            status_code=400,
        )
    policy = DiscoveryPolicy(require_https=False, validate_issuer=True)
    disco = get_discovery_document(
        DiscoveryDocumentRequest(address=disco_endpoint.url, policy=policy),
        http_client=http_client,
    )

    if not disco.is_successful:
        session.result["status"] = "error"
        session.result["error"] = f"discovery_failed: {disco.error}"
        _store_test_result(session)
        return HTMLResponse(
            content=f"<h1>Discovery Failed</h1><p>{disco.error}</p>",
            status_code=502,
        )

    # OIDC Discovery 1.0 §4.3: issuer in document MUST match the URL used to retrieve it
    if not disco.issuer:
        error_msg = "Discovery document missing required 'issuer' field"
        logger.error(error_msg)
        session.result["status"] = "error"
        session.result["error"] = f"missing_issuer: {error_msg}"
        _store_test_result(session)
        return HTMLResponse(
            content=f"<h1>Missing Issuer</h1><p>{error_msg}</p>",
            status_code=502,
        )
    if disco.issuer != issuer:
        error_msg = (
            f"Issuer mismatch: discovery document issuer '{disco.issuer}' "
            f"does not match expected '{issuer}'"
        )
        logger.error(error_msg)
        session.result["status"] = "error"
        session.result["error"] = f"issuer_mismatch: {error_msg}"
        _store_test_result(session)
        return HTMLResponse(
            content=f"<h1>Issuer Mismatch</h1><p>{error_msg}</p>",
            status_code=502,
        )

    return disco, disco_endpoint


def _handle_callback(request_url: str) -> HTMLResponse | JSONResponse:
    """Common callback handler for GET and POST response modes."""
    http_client = _get_http_client()

    # Parse callback parameters
    try:
        cb_response = parse_authorize_callback_response(str(request_url))
    except PyIdentityModelException as exc:
        logger.error("Callback parse error: %s", exc)
        return HTMLResponse(
            content=f"<h1>Callback Error</h1><p>{exc}</p>", status_code=400
        )

    # Look up session by state
    state_value = cb_response.state
    if state_value is None or state_value not in sessions:
        logger.error("Unknown state: %s", state_value)
        return HTMLResponse(
            content="<h1>Error</h1><p>Unknown or missing state parameter</p>",
            status_code=400,
        )

    session = sessions.pop(state_value)

    # Validate state
    state_result = validate_authorize_callback_state(cb_response, session.state)
    if not state_result.is_valid:
        session.result["status"] = "error"
        session.result["error"] = f"state_validation: {state_result.result.value}"
        _store_test_result(session)
        return HTMLResponse(
            content=f"<h1>State Validation Failed</h1><p>{state_result.result.value}</p>",
            status_code=400,
        )

    # Check for error response from OP
    if not cb_response.is_successful:
        session.result["status"] = "error"
        session.result["error"] = cb_response.error
        session.result["error_description"] = cb_response.error_description
        _store_test_result(session)
        return HTMLResponse(
            content=f"<h1>OP Error</h1><p>{cb_response.error}: {cb_response.error_description}</p>",
            status_code=400,
        )

    # Fetch discovery document (not cached in harness, each test may use different OP)
    disco_result = _fetch_and_validate_discovery(session.issuer, http_client, session)
    if isinstance(disco_result, HTMLResponse):
        return disco_result
    disco, disco_endpoint = disco_result

    # Exchange authorization code for tokens
    if disco.token_endpoint is None:
        session.result["status"] = "error"
        session.result["error"] = "missing_token_endpoint"
        _store_test_result(session)
        return HTMLResponse(
            content="<h1>Discovery Error</h1><p>Discovery document missing token_endpoint</p>",
            status_code=502,
        )
    if cb_response.code is None:
        session.result["status"] = "error"
        session.result["error"] = "missing_code"
        _store_test_result(session)
        return HTMLResponse(
            content="<h1>Callback Error</h1><p>Authorization callback missing code parameter</p>",
            status_code=400,
        )
    token_response = request_authorization_code_token(
        AuthorizationCodeTokenRequest(
            address=disco.token_endpoint,
            client_id=session.client_id,
            code=cb_response.code,
            redirect_uri=session.redirect_uri,
            code_verifier=session.code_verifier,
            client_secret=session.client_secret if session.client_secret else None,
        ),
        http_client=http_client,
    )

    if not token_response.is_successful:
        session.result["status"] = "error"
        session.result["error"] = f"token_exchange: {token_response.error}"
        _store_test_result(session)
        return HTMLResponse(
            content=f"<h1>Token Exchange Failed</h1><p>{token_response.error}</p>",
            status_code=400,
        )

    if token_response.token is None:
        session.result["status"] = "error"
        session.result["error"] = "missing_token_data"
        _store_test_result(session)
        return HTMLResponse(
            content="<h1>Token Error</h1><p>Token response missing token data</p>",
            status_code=502,
        )
    token_data = token_response.token
    id_token_jwt = token_data.get("id_token")
    access_token = token_data.get("access_token")

    # Validate the ID token.
    # NOTE: We intentionally do NOT clear the JWKS cache before validation.
    # The library's built-in retry-on-signature-failure path (JWKS cache refresh
    # on kid mismatch / sig failure) must be exercised here — it is required by
    # the rp-key-rotation-op-sign-key conformance tests. See PR #310.
    claims: dict = {}
    if id_token_jwt:
        try:
            claims = validate_token(
                jwt=id_token_jwt,
                token_validation_config=TokenValidationConfig(
                    perform_disco=True,
                    audience=session.client_id,
                    issuer=disco.issuer,
                    options={"verify_exp": True, "require": ["sub", "iat"]},
                    require_https=False,
                ),
                disco_doc_address=disco_endpoint.url,
                http_client=http_client,
            )
        except TokenValidationException as exc:
            session.result["status"] = "error"
            session.result["error"] = f"id_token_validation: {exc.message}"
            _store_test_result(session)
            return HTMLResponse(
                content=f"<h1>ID Token Validation Failed</h1><p>{exc.message}</p>",
                status_code=400,
            )

        # Validate nonce
        token_nonce = claims.get("nonce")
        if token_nonce != session.nonce:
            session.result["status"] = "error"
            session.result["error"] = (
                f"nonce_mismatch: expected={session.nonce}, got={token_nonce}"
            )
            _store_test_result(session)
            return HTMLResponse(
                content=f"<h1>Nonce Mismatch</h1>"
                f"<p>Expected: {session.nonce}, Got: {token_nonce}</p>",
                status_code=400,
            )

    # Fetch UserInfo (if endpoint is available and we have an access token)
    userinfo_claims: dict = {}
    if access_token and disco.userinfo_endpoint and not session.skip_userinfo:
        try:
            userinfo_response = get_userinfo(
                UserInfoRequest(
                    address=disco.userinfo_endpoint,
                    token=access_token,
                    expected_sub=claims.get("sub"),
                ),
                http_client=http_client,
            )
            if userinfo_response.is_successful:
                userinfo_claims = userinfo_response.claims or {}
            else:
                # UserInfo errors should be reported but may not be fatal
                logger.warning("UserInfo error: %s", userinfo_response.error)
                session.result["userinfo_error"] = userinfo_response.error
        except PyIdentityModelException as exc:
            logger.warning("UserInfo exception: %s", exc)
            session.result["userinfo_error"] = str(exc)

    # Store successful result
    session.result["status"] = "success"
    session.result["id_token_claims"] = claims
    session.result["userinfo_claims"] = userinfo_claims
    session.result["access_token"] = access_token
    _store_test_result(session)

    logger.info(
        "Callback successful for issuer=%s, sub=%s", session.issuer, claims.get("sub")
    )

    return HTMLResponse(
        content=(
            "<h1>Authentication Successful</h1>"
            f"<p>Subject: {claims.get('sub', 'N/A')}</p>"
            f"<p>Issuer: {claims.get('iss', 'N/A')}</p>"
        ),
        status_code=200,
    )


@app.get("/callback", response_model=None)
def callback_get(request: Request) -> HTMLResponse | JSONResponse:
    """Handle authorization callback (query string mode)."""
    return _handle_callback(str(request.url))


@app.post("/callback", response_model=None)
async def callback_post(request: Request) -> HTMLResponse | JSONResponse:
    """Handle authorization callback (form_post mode).

    Async to support ``await request.form()``, with the blocking
    ``_handle_callback`` offloaded to a threadpool.
    """
    form_data = await request.form()
    params = urlencode(dict(form_data))
    callback_url = f"{RP_BASE_URL}/callback?{params}"
    return await run_in_threadpool(_handle_callback, callback_url)


@app.get("/results/{test_id}")
def get_result(test_id: str) -> JSONResponse:
    """Retrieve the result of a completed test flow."""
    if test_id in test_results:
        session = test_results[test_id]
        return JSONResponse(content=session.result)
    return JSONResponse(status_code=404, content={"error": "not_found"})


def _store_test_result(session: AuthSession) -> None:
    """Store session result indexed by test_id if available."""
    test_id = session.result.get("test_id")
    if test_id:
        test_results[test_id] = session
