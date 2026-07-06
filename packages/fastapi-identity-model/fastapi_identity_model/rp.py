"""Relying-Party (OIDC login) router for FastAPI.

``build_oidc_router`` returns a mountable :class:`fastapi.APIRouter` implementing
the authorization-code + PKCE login flow against any OpenID Connect provider,
using the async ``py_identity_model.aio`` API for all protocol work:

    from fastapi import FastAPI
    from starlette.middleware.sessions import SessionMiddleware
    from fastapi_identity_model import OIDCSettings, build_oidc_router

    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="...")   # required
    app.include_router(build_oidc_router(settings), prefix="/auth")

Routes: ``GET /login`` → provider, ``GET /callback`` (exchange + validate +
nonce + UserInfo), ``POST /logout``. The transient PKCE/state/nonce are kept
under a separate ``<session_key>.flow`` entry and popped on callback (single
use); the resulting identity is written to ``session[session_key]`` only after
a verified ID token, so reading ``session[session_key]`` never observes an
in-flight login. Logout is POST-only so a cross-site GET cannot force it.

Security note: ``SessionMiddleware`` signs but does **not** encrypt the cookie.
Identity claims stored there are tamper-proof but readable by the client. Raw
tokens are stored only when ``store_tokens=True`` — enable that only with an
encrypted or server-side session store. Logout clears the local session only;
it does not call the provider's ``end_session_endpoint``.
"""

from __future__ import annotations

import logging
import secrets
from typing import TYPE_CHECKING

from fastapi import APIRouter, HTTPException, Request, status
from starlette.responses import RedirectResponse

from py_identity_model import PyIdentityModelException
from py_identity_model.aio import (
    AuthorizationCodeTokenRequest,
    DiscoveryDocumentRequest,
    DiscoveryDocumentResponse,
    TokenValidationConfig,
    UserInfoRequest,
    build_authorization_url,
    generate_pkce_pair,
    get_discovery_document,
    get_userinfo,
    parse_authorize_callback_response,
    request_authorization_code_token,
    validate_authorize_callback_state,
    validate_token,
)


if TYPE_CHECKING:
    from .config import OIDCSettings


logger = logging.getLogger("fastapi_identity_model")

_STATE_TOKEN_BYTES = 32


def _flow_key(session_key: str) -> str:
    """Session key holding transient login-flow state (state/nonce/verifier).

    Kept separate from *session_key* (which holds the final identity) so a
    consumer reading ``session[session_key]`` never observes an in-flight
    login as an authenticated identity, and never sees the ``code_verifier``.
    """
    return f"{session_key}.flow"


def _require_session(request: Request) -> None:
    """Fail with a clear error when ``SessionMiddleware`` is not installed."""
    if "session" not in request.scope:
        raise RuntimeError(
            "SessionMiddleware is required by the OIDC router but is not "
            "installed. Add: app.add_middleware(SessionMiddleware, secret_key=...)"
        )


async def _discover(settings: OIDCSettings) -> DiscoveryDocumentResponse:
    disco = await get_discovery_document(
        DiscoveryDocumentRequest(address=settings.discovery_url),
    )
    if not disco.is_successful:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"OIDC discovery failed: {disco.error}",
        )
    return disco


def _require_endpoint(value: str | None, name: str) -> str:
    if not value:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Provider discovery is missing '{name}'",
        )
    return value


async def _login(
    request: Request, settings: OIDCSettings, session_key: str
) -> RedirectResponse:
    _require_session(request)
    disco = await _discover(settings)
    authorization_endpoint = _require_endpoint(
        disco.authorization_endpoint, "authorization_endpoint"
    )
    code_verifier, code_challenge = generate_pkce_pair()
    state = secrets.token_urlsafe(_STATE_TOKEN_BYTES)
    nonce = secrets.token_urlsafe(_STATE_TOKEN_BYTES)
    request.session[_flow_key(session_key)] = {
        "state": state,
        "nonce": nonce,
        "code_verifier": code_verifier,
    }
    url = build_authorization_url(
        authorization_endpoint=authorization_endpoint,
        client_id=settings.client_id,
        redirect_uri=settings.redirect_uri,
        scope=settings.scope,
        state=state,
        nonce=nonce,
        code_challenge=code_challenge,
        code_challenge_method="S256",
    )
    return RedirectResponse(url, status_code=status.HTTP_302_FOUND)


async def _exchange_code(
    settings: OIDCSettings,
    disco: DiscoveryDocumentResponse,
    code: str,
    code_verifier: str,
) -> dict:
    """Exchange the authorization code and return the token dict."""
    token_endpoint = _require_endpoint(disco.token_endpoint, "token_endpoint")
    tok = await request_authorization_code_token(
        AuthorizationCodeTokenRequest(
            address=token_endpoint,
            client_id=settings.client_id,
            code=code,
            redirect_uri=settings.redirect_uri,
            code_verifier=code_verifier,
            client_secret=settings.client_secret or None,
        ),
    )
    if not tok.is_successful or not tok.token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Token exchange failed: {tok.error}",
        )
    return tok.token


async def _validate_id_token(
    settings: OIDCSettings,
    disco: DiscoveryDocumentResponse,
    id_token: str,
    expected_nonce: str,
) -> dict:
    """Validate the ID token (signature/iss/aud/exp/required claims) and bind the nonce."""
    # Guard the issuer explicitly: a discovery doc missing ``issuer`` would
    # otherwise pass ``issuer=None`` and silently disable issuer verification.
    issuer = _require_endpoint(disco.issuer, "issuer")
    try:
        claims = await validate_token(
            jwt=id_token,
            token_validation_config=TokenValidationConfig(
                perform_disco=True,
                audience=settings.client_id,
                issuer=issuer,
                options={"verify_exp": True, "require": ["sub", "iat", "exp"]},
            ),
            disco_doc_address=settings.discovery_url,
        )
    except PyIdentityModelException as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"ID token validation failed: {exc}",
        ) from exc

    # Nonce binding is the RP's responsibility — the library does not check it.
    if claims.get("nonce") != expected_nonce:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nonce mismatch",
        )
    return claims


async def _fetch_userinfo(
    disco: DiscoveryDocumentResponse,
    access_token: str | None,
    expected_sub: str | None,
) -> dict:
    """Fetch UserInfo, enforcing the OIDC Core 5.3.2 ``sub`` match as a hard gate.

    An unavailable UserInfo endpoint (no endpoint, or a transient fetch
    failure) is tolerated — identity is anchored on the validated ID token.
    But a *successful* fetch whose ``sub`` disagrees with the ID token is a
    token-substitution signal and must abort the login, not be swallowed.
    """
    userinfo_endpoint = disco.userinfo_endpoint
    if not access_token or not userinfo_endpoint:
        return {}
    # Fetch without expected_sub so is_successful reflects only the fetch;
    # the sub comparison is enforced here so a mismatch fails the login.
    ui = await get_userinfo(
        UserInfoRequest(address=userinfo_endpoint, token=access_token),
    )
    if not ui.is_successful:
        logger.warning("UserInfo fetch failed, continuing on ID token: %s", ui.error)
        return {}
    claims = ui.claims or {}
    if expected_sub is not None and claims.get("sub") != expected_sub:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="UserInfo subject does not match ID token subject",
        )
    return claims


async def _callback(
    request: Request,
    settings: OIDCSettings,
    session_key: str,
    *,
    store_tokens: bool,
) -> RedirectResponse:
    _require_session(request)
    # Pop the flow state so it is single-use: a failed or replayed callback
    # cannot reuse the same state/verifier for another attempt.
    flow = request.session.pop(_flow_key(session_key), None)
    if not flow or not {"state", "nonce", "code_verifier"} <= flow.keys():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active login flow in session",
        )

    try:
        cb = parse_authorize_callback_response(str(request.url))
    except PyIdentityModelException as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Malformed authorization callback: {exc}",
        ) from exc
    if not cb.is_successful:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Authorization error: {cb.error}",
        )
    if not validate_authorize_callback_state(cb, flow["state"]).is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="State mismatch (possible CSRF)",
        )
    if cb.code is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authorization response missing code",
        )

    disco = await _discover(settings)
    token = await _exchange_code(settings, disco, cb.code, flow["code_verifier"])
    id_token = token.get("id_token")
    access_token = token.get("access_token")

    # An OIDC login flow (openid scope, nonce sent) requires a verified ID
    # token. Refuse to establish a session on a token response that omits it
    # rather than degrading to an unauthenticated "logged-in" session.
    if not id_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Provider did not return an ID token",
        )
    claims = await _validate_id_token(settings, disco, id_token, flow["nonce"])

    userinfo = await _fetch_userinfo(disco, access_token, claims.get("sub"))

    session_data: dict = {
        "sub": claims.get("sub"),
        "claims": claims,
        "userinfo": userinfo,
    }
    if store_tokens:
        session_data["tokens"] = {
            "access_token": access_token,
            "refresh_token": token.get("refresh_token"),
            "id_token": id_token,
        }
    request.session[session_key] = session_data

    return RedirectResponse(
        settings.post_login_redirect,
        status_code=status.HTTP_302_FOUND,
    )


def build_oidc_router(
    settings: OIDCSettings,
    *,
    session_key: str = "oidc",
    store_tokens: bool = False,
) -> APIRouter:
    """Build an OIDC relying-party router.

    Args:
        settings: Provider/client configuration.
        session_key: Key under which flow + identity state is kept in the session.
        store_tokens: When True, also persist the access/refresh/id tokens in the
            session (requires an encrypted or server-side session store).

    Returns:
        An ``APIRouter`` with ``/login``, ``/callback`` and ``/logout`` routes.
    """
    if not settings.redirect_uri:
        raise ValueError(
            "build_oidc_router requires settings.redirect_uri (the provider "
            "callback URL); it is only optional for resource-server-only setups."
        )
    router = APIRouter()

    @router.get("/login")
    async def login(request: Request) -> RedirectResponse:
        return await _login(request, settings, session_key)

    @router.get("/callback")
    async def callback(request: Request) -> RedirectResponse:
        return await _callback(
            request, settings, session_key, store_tokens=store_tokens
        )

    @router.post("/logout")
    async def logout(request: Request) -> RedirectResponse:
        # POST-only: a state-changing session mutation must not be triggerable
        # by a cross-site GET (e.g. an <img> tag) under a Lax cookie.
        _require_session(request)
        request.session.pop(session_key, None)
        request.session.pop(_flow_key(session_key), None)
        return RedirectResponse(
            settings.post_logout_redirect,
            status_code=status.HTTP_303_SEE_OTHER,
        )

    return router
