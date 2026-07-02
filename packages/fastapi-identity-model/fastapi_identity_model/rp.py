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
nonce + UserInfo), ``GET /logout``. The transient PKCE/state/nonce and the
resulting identity are kept in ``request.session`` (Starlette ``SessionMiddleware``).

Security note: ``SessionMiddleware`` signs but does **not** encrypt the cookie.
Identity claims stored there are tamper-proof but readable by the client. Raw
tokens are stored only when ``store_tokens=True`` — enable that only with an
encrypted or server-side session store.
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
    disco = await _discover(settings)
    authorization_endpoint = _require_endpoint(
        disco.authorization_endpoint, "authorization_endpoint"
    )
    code_verifier, code_challenge = generate_pkce_pair()
    state = secrets.token_urlsafe(_STATE_TOKEN_BYTES)
    nonce = secrets.token_urlsafe(_STATE_TOKEN_BYTES)
    request.session[session_key] = {
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
    try:
        claims = await validate_token(
            jwt=id_token,
            token_validation_config=TokenValidationConfig(
                perform_disco=True,
                audience=settings.client_id,
                issuer=disco.issuer,
                options={"verify_exp": True, "require": ["sub", "iat"]},
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
    userinfo_endpoint = disco.userinfo_endpoint
    if not access_token or not userinfo_endpoint:
        return {}
    ui = await get_userinfo(
        UserInfoRequest(
            address=userinfo_endpoint,
            token=access_token,
            expected_sub=expected_sub,
        ),
    )
    return ui.claims or {} if ui.is_successful else {}


async def _callback(
    request: Request,
    settings: OIDCSettings,
    session_key: str,
    *,
    store_tokens: bool,
) -> RedirectResponse:
    flow = request.session.get(session_key)
    if not flow or "state" not in flow:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active login flow in session",
        )

    cb = parse_authorize_callback_response(str(request.url))
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

    claims: dict = {}
    if id_token:
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
    router = APIRouter()

    @router.get("/login")
    async def login(request: Request) -> RedirectResponse:
        return await _login(request, settings, session_key)

    @router.get("/callback")
    async def callback(request: Request) -> RedirectResponse:
        return await _callback(
            request, settings, session_key, store_tokens=store_tokens
        )

    @router.get("/logout")
    async def logout(request: Request) -> RedirectResponse:
        request.session.pop(session_key, None)
        return RedirectResponse(
            settings.post_logout_redirect,
            status_code=status.HTTP_302_FOUND,
        )

    return router
