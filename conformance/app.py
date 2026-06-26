"""OIDC RP conformance test harness.

Thin FastAPI application that acts as an OpenID Connect Relying Party,
using py-identity-model's public API to exercise all RP conformance tests.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import html
import logging
import os
from pathlib import Path
import re
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
    clear_jwks_cache,
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
from py_identity_model.sync.token_validation import (
    clear_discovery_cache,
)


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("conformance-rp")

app = FastAPI(title="py-identity-model Conformance RP")

# ---------------------------------------------------------------------------
# Per-test RP log capture (clientSideData for OIDF RP certification)
# ---------------------------------------------------------------------------
#
# OIDF RP certification requires one log file per test, named by the test id,
# demonstrating the RP's behaviour — in particular that negative tests are
# rejected (https://openid.net/certification/connect_rp_submission/). The
# conformance suite only logs the OP side, so the RP must produce these itself.
#
# The runner drives tests strictly sequentially and tells the harness which
# test is active via /authorize, /discover and /callback, so a process-global
# pointer plus a logging handler that routes records to the active test's file
# is sufficient. RP_LOG_DIR defaults to an absolute path derived from this
# file's location so the harness and the (separately-launched) runner agree on
# it regardless of working directory.

_active_test: tuple[str, str] | None = None


def _rp_log_base() -> Path:
    """Base directory for per-test RP logs (env-overridable)."""
    return Path(
        os.environ.get("RP_LOG_DIR")
        or (Path(__file__).parent / "results" / "hosted" / "rp-logs")
    )


def _rp_log_path(profile: str, test_name: str) -> Path:
    """Path to the log file for ``test_name`` within ``profile`` (dir created).

    ``profile`` and ``test_name`` arrive as request parameters, so the path is
    hardened two ways: every character outside ``[A-Za-z0-9._-]`` is replaced
    (removing any path separators), and the resolved path is verified to stay
    inside the log base — a value that somehow escaped raises rather than
    writing outside the base directory.
    """
    base = _rp_log_base().resolve()
    safe_profile = re.sub(r"[^A-Za-z0-9._-]", "_", profile) or "default"
    safe_test = re.sub(r"[^A-Za-z0-9._-]", "_", test_name) or "unknown"
    candidate = (base / safe_profile / f"{safe_test}.log").resolve()
    if base not in candidate.parents:
        raise ValueError(
            f"refusing unsafe RP log path (profile={profile!r}, test={test_name!r})"
        )
    candidate.parent.mkdir(parents=True, exist_ok=True)
    return candidate


def _set_active_test(profile: str | None, test_name: str | None) -> None:
    """Point per-test logging at ``test_name`` (or clear it when no test)."""
    global _active_test
    _active_test = (profile or "", test_name) if test_name else None


class _PerTestLogRouter(logging.Handler):
    """Appends harness + library log records to the active test's log file."""

    def emit(self, record: logging.LogRecord) -> None:
        test = _active_test
        if not test or not test[1]:
            return
        try:
            with _rp_log_path(test[0], test[1]).open("a", encoding="utf-8") as fh:
                fh.write(self.format(record) + "\n")
        except (OSError, ValueError):
            # Never let log capture break the flow under test.
            pass


def _install_rp_log_router() -> None:
    router = _PerTestLogRouter()
    router.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s")
    )
    for name in ("conformance-rp", "py_identity_model"):
        logging.getLogger(name).addHandler(router)
    # Capture the library's own validation detail in the per-test logs.
    logging.getLogger("py_identity_model").setLevel(logging.DEBUG)


_install_rp_log_router()

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
    # Per-test RP-log routing (recovered in /callback via the session)
    test_name: str = ""
    profile: str = ""
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


@app.post("/clear-cache")
def clear_cache() -> dict:
    """Clear library discovery and JWKS caches between conformance tests.

    The conformance suite reconfigures the OP's JWKS between test modules.
    Without clearing caches, validate_token uses stale keys and hangs on
    retry backoff (3 retries x 30s timeout = ~2 min timeout per test).
    """
    _set_active_test(None, None)
    clear_discovery_cache()
    clear_jwks_cache()
    logger.info("Cleared discovery and JWKS caches")
    return {"status": "ok", "cleared": ["discovery", "jwks"]}


@app.get("/discover", response_model=None)
def discover(
    issuer: str = Query(..., description="Issuer URL for this test"),
    test_id: str = Query("", description="Test module ID for result tracking"),
    test_name: str = Query("", description="Test module name for RP log capture"),
    profile: str = Query("", description="Profile/plan name for RP log capture"),
) -> JSONResponse:
    """Fetch discovery document (and JWKS) without starting an auth flow.

    Used for Config RP discovery-only tests where the suite just needs to
    observe the RP fetching the openid-configuration endpoint.
    """
    _set_active_test(profile, test_name)
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
            content={"error": "invalid_issuer", "detail": "Invalid issuer URL"},
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
    test_name: str = Query("", description="Test module name for RP log capture"),
    profile: str = Query("", description="Profile/plan name for RP log capture"),
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
    _set_active_test(profile, test_name)
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
            content={"error": "invalid_issuer", "detail": "Invalid issuer URL"},
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
        test_name=test_name,
        profile=profile,
    )
    sessions[state] = session
    if test_id:
        session.result["test_id"] = test_id

    logger.info(
        "ACCEPTED discovery: issuer '%s' matches expected; redirecting to OP", issuer
    )
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
            content="<h1>Invalid Issuer</h1><p>Discovery URL is invalid</p>",
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
            content=f"<h1>Discovery Failed</h1><p>{html.escape(str(disco.error))}</p>",
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
            content=f"<h1>Missing Issuer</h1><p>{html.escape(error_msg)}</p>",
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
            content=f"<h1>Issuer Mismatch</h1><p>{html.escape(error_msg)}</p>",
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
            content="<h1>Callback Error</h1><p>Failed to parse callback</p>",
            status_code=400,
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
    # Route this flow's logs to the test that started it (recovered via state).
    _set_active_test(session.profile, session.test_name)

    # Validate state
    state_result = validate_authorize_callback_state(cb_response, session.state)
    if not state_result.is_valid:
        session.result["status"] = "error"
        session.result["error"] = f"state_validation: {state_result.result.value}"
        logger.error("REJECTED: state validation failed: %s", state_result.result.value)
        _store_test_result(session)
        return HTMLResponse(
            content=(
                "<h1>State Validation Failed</h1>"
                f"<p>{html.escape(state_result.result.value)}</p>"
            ),
            status_code=400,
        )

    # Check for error response from OP
    if not cb_response.is_successful:
        session.result["status"] = "error"
        session.result["error"] = cb_response.error
        session.result["error_description"] = cb_response.error_description
        logger.error(
            "REJECTED: OP returned error response: %s (%s)",
            cb_response.error,
            cb_response.error_description,
        )
        _store_test_result(session)
        return HTMLResponse(
            content=(
                "<h1>OP Error</h1>"
                f"<p>{html.escape(str(cb_response.error))}: "
                f"{html.escape(str(cb_response.error_description))}</p>"
            ),
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
        logger.error("REJECTED: token exchange failed: %s", token_response.error)
        _store_test_result(session)
        return HTMLResponse(
            content=(
                "<h1>Token Exchange Failed</h1>"
                f"<p>{html.escape(str(token_response.error))}</p>"
            ),
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
    #
    # CRITICAL: do NOT pass http_client= to validate_token here.
    #
    # When http_client is provided, sync/token_validation._discover_and_resolve_key
    # takes the non-cached branch (calling get_jwks directly) and the library's
    # JWKS cache — and therefore its cache-miss-triggered retry path — is
    # structurally bypassed. That makes the retry-on-signature-failure logic
    # from PR #310 unreachable from the harness, and the rp-key-rotation-*
    # conformance tests pass for the wrong reason (fresh JWKS on every call,
    # never triggering the sig-fail → refresh → retry sequence the tests exist
    # to exercise). See #327 for the full analysis.
    #
    # Letting validate_token use its default (thread-local) HTTPClient routes
    # through _get_cached_jwks → first validation uses cached keys → sig failure
    # triggers _retry_with_refreshed_jwks → retry succeeds with rotated keys.
    # That is the behavior the rp-key-rotation conformance tests are designed
    # to verify, and it only works if we let the library own the HTTP client.
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
            )
        except TokenValidationException as exc:
            session.result["status"] = "error"
            session.result["error"] = f"id_token_validation: {exc.message}"
            logger.error("REJECTED: id_token validation failed: %s", exc.message)
            _store_test_result(session)
            return HTMLResponse(
                content=(
                    "<h1>ID Token Validation Failed</h1>"
                    f"<p>{html.escape(str(exc.message))}</p>"
                ),
                status_code=400,
            )

        logger.info(
            "ACCEPTED: id_token validated by py-identity-model "
            "(signature, issuer, audience, expiry)"
        )

        # Validate nonce
        token_nonce = claims.get("nonce")
        if token_nonce != session.nonce:
            session.result["status"] = "error"
            session.result["error"] = (
                f"nonce_mismatch: expected={session.nonce}, got={token_nonce}"
            )
            logger.error(
                "REJECTED: nonce mismatch (expected=%s, got=%s)",
                session.nonce,
                token_nonce,
            )
            _store_test_result(session)
            return HTMLResponse(
                content=(
                    "<h1>Nonce Mismatch</h1>"
                    f"<p>Expected: {html.escape(str(session.nonce))}, "
                    f"Got: {html.escape(str(token_nonce))}</p>"
                ),
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
                # OIDC Core 1.0 §5.3.4: sub mismatch is a fatal error.
                # The RP MUST reject the UserInfo response if sub differs
                # from the ID token sub.
                error_msg = userinfo_response.error
                logger.error(
                    "REJECTED: UserInfo validation failed (sub mismatch per "
                    "OIDC Core §5.3.4): %s",
                    error_msg,
                )
                session.result["status"] = "error"
                session.result["error"] = f"userinfo_validation: {error_msg}"
                _store_test_result(session)
                return HTMLResponse(
                    content=(
                        "<h1>UserInfo Validation Failed</h1>"
                        f"<p>{html.escape(str(error_msg))}</p>"
                    ),
                    status_code=400,
                )
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
        "ACCEPTED: authentication successful for issuer=%s, sub=%s",
        session.issuer,
        claims.get("sub"),
    )

    # Build response body with ID token and UserInfo claims so the conformance
    # suite can verify the RP fetched and displayed them. All interpolated
    # values originate from the IdP (claims, error messages) and must be
    # HTML-escaped before rendering — see #381.
    claim_lines = [
        f"<p>Subject: {html.escape(str(claims.get('sub', 'N/A')))}</p>",
        f"<p>Issuer: {html.escape(str(claims.get('iss', 'N/A')))}</p>",
    ]
    if userinfo_claims:
        claim_lines.append("<h2>UserInfo Claims</h2>")
        for key, value in userinfo_claims.items():
            claim_lines.append(
                f"<p>{html.escape(str(key))}: {html.escape(str(value))}</p>"
            )

    return HTMLResponse(
        content="<h1>Authentication Successful</h1>" + "\n".join(claim_lines),
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

    Starlette's ``FormData`` is a multi-dict — a single form key can
    carry multiple values. ``dict(form_data)`` silently drops all but
    the first value for such keys, which would corrupt any response
    that legitimately submits a repeated field. Use ``multi_items()``
    so every (key, value) pair survives the urlencode round-trip.
    """
    form_data = await request.form()
    params = urlencode(list(form_data.multi_items()))
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
