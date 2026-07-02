from types import SimpleNamespace
from unittest.mock import AsyncMock
from urllib.parse import parse_qs, urlparse

from fastapi import FastAPI, Request
import httpx
import pytest
from starlette.middleware.sessions import SessionMiddleware

from fastapi_identity_model import OIDCSettings, build_oidc_router, rp
from py_identity_model import TokenValidationException


pytestmark = pytest.mark.unit

SETTINGS = OIDCSettings(
    discovery_url="https://op/.well-known/openid-configuration",
    client_id="cid",
    redirect_uri="http://localhost:8000/auth/callback",
)

_DISCO = SimpleNamespace(
    is_successful=True,
    error=None,
    authorization_endpoint="https://op/authorize",
    token_endpoint="https://op/token",
    userinfo_endpoint="https://op/userinfo",
    issuer="https://op",
)


def _patch(monkeypatch, *, disco=_DISCO, token=None, claims=None, userinfo=None):
    monkeypatch.setattr(rp, "get_discovery_document", AsyncMock(return_value=disco))
    monkeypatch.setattr(
        rp,
        "request_authorization_code_token",
        AsyncMock(
            return_value=SimpleNamespace(
                is_successful=True,
                error=None,
                token=token
                if token is not None
                else {"id_token": "idt", "access_token": "at"},
            )
        ),
    )
    monkeypatch.setattr(
        rp,
        "validate_token",
        AsyncMock(return_value=claims if claims is not None else {"sub": "user-1"}),
    )
    monkeypatch.setattr(
        rp,
        "get_userinfo",
        AsyncMock(
            return_value=SimpleNamespace(
                is_successful=True,
                claims=userinfo
                if userinfo is not None
                else {"sub": "user-1", "email": "u@e"},
            )
        ),
    )


def _app(store_tokens: bool = False) -> FastAPI:
    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="test-secret")
    app.include_router(
        build_oidc_router(SETTINGS, store_tokens=store_tokens), prefix="/auth"
    )

    @app.get("/me")
    async def me(request: Request):
        return request.session.get("oidc", {})

    return app


def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    )


async def _login(client: httpx.AsyncClient) -> tuple[str, str]:
    resp = await client.get("/auth/login")
    assert resp.status_code == 302
    q = parse_qs(urlparse(resp.headers["location"]).query)
    assert q["redirect_uri"][0] == SETTINGS.redirect_uri
    assert q["code_challenge_method"][0] == "S256"
    return q["state"][0], q["nonce"][0]


async def test_login_redirects_to_provider(monkeypatch):
    _patch(monkeypatch)
    async with _client(_app()) as client:
        resp = await client.get("/auth/login")
    assert resp.status_code == 302
    assert resp.headers["location"].startswith("https://op/authorize")


async def test_full_login_flow(monkeypatch):
    _patch(monkeypatch)
    async with _client(_app()) as client:
        state, nonce = await _login(client)
        rp.validate_token.return_value = {"sub": "user-1", "nonce": nonce}

        resp = await client.get(f"/auth/callback?code=abc&state={state}")
        assert resp.status_code == 302
        assert resp.headers["location"] == "/"

        me = (await client.get("/me")).json()
    assert me["sub"] == "user-1"
    assert me["userinfo"] == {"sub": "user-1", "email": "u@e"}
    assert "tokens" not in me


async def test_store_tokens_persists_tokens(monkeypatch):
    _patch(monkeypatch)
    async with _client(_app(store_tokens=True)) as client:
        state, nonce = await _login(client)
        rp.validate_token.return_value = {"sub": "user-1", "nonce": nonce}
        await client.get(f"/auth/callback?code=abc&state={state}")
        me = (await client.get("/me")).json()
    assert me["tokens"]["access_token"] == "at"


async def test_callback_without_active_flow(monkeypatch):
    _patch(monkeypatch)
    async with _client(_app()) as client:
        resp = await client.get("/auth/callback?code=abc&state=xyz")
    assert resp.status_code == 400
    assert "No active login flow" in resp.json()["detail"]


async def test_callback_state_mismatch(monkeypatch):
    _patch(monkeypatch)
    async with _client(_app()) as client:
        await _login(client)
        resp = await client.get("/auth/callback?code=abc&state=wrong")
    assert resp.status_code == 400
    assert "State mismatch" in resp.json()["detail"]


async def test_callback_missing_code(monkeypatch):
    _patch(monkeypatch)
    async with _client(_app()) as client:
        state, _ = await _login(client)
        resp = await client.get(f"/auth/callback?state={state}")
    assert resp.status_code == 400
    assert "missing code" in resp.json()["detail"]


async def test_login_discovery_failure(monkeypatch):
    _patch(monkeypatch, disco=SimpleNamespace(is_successful=False, error="down"))
    async with _client(_app()) as client:
        resp = await client.get("/auth/login")
    assert resp.status_code == 502
    assert "discovery failed" in resp.json()["detail"].lower()


async def test_callback_token_exchange_failure(monkeypatch):
    _patch(monkeypatch)
    async with _client(_app()) as client:
        state, _ = await _login(client)
        rp.request_authorization_code_token.return_value = SimpleNamespace(
            is_successful=False, error="invalid_grant", token=None
        )
        resp = await client.get(f"/auth/callback?code=abc&state={state}")
    assert resp.status_code == 400
    assert "Token exchange failed" in resp.json()["detail"]


async def test_callback_invalid_id_token(monkeypatch):
    _patch(monkeypatch)
    async with _client(_app()) as client:
        state, _ = await _login(client)
        rp.validate_token.side_effect = TokenValidationException("bad iss")
        resp = await client.get(f"/auth/callback?code=abc&state={state}")
    assert resp.status_code == 401
    assert "ID token validation failed" in resp.json()["detail"]


async def test_callback_nonce_mismatch(monkeypatch):
    _patch(monkeypatch)
    async with _client(_app()) as client:
        state, _ = await _login(client)
        rp.validate_token.return_value = {"sub": "user-1", "nonce": "attacker-nonce"}
        resp = await client.get(f"/auth/callback?code=abc&state={state}")
    assert resp.status_code == 401
    assert "Nonce mismatch" in resp.json()["detail"]


async def test_callback_userinfo_failure_is_tolerated(monkeypatch):
    _patch(monkeypatch)
    async with _client(_app()) as client:
        state, nonce = await _login(client)
        rp.validate_token.return_value = {"sub": "user-1", "nonce": nonce}
        rp.get_userinfo.return_value = SimpleNamespace(is_successful=False, claims=None)
        resp = await client.get(f"/auth/callback?code=abc&state={state}")
        assert resp.status_code == 302
        assert (await client.get("/me")).json()["userinfo"] == {}


async def test_logout_clears_session(monkeypatch):
    _patch(monkeypatch)
    async with _client(_app()) as client:
        state, nonce = await _login(client)
        rp.validate_token.return_value = {"sub": "user-1", "nonce": nonce}
        await client.get(f"/auth/callback?code=abc&state={state}")
        assert (await client.get("/me")).json().get("sub") == "user-1"

        resp = await client.get("/auth/logout")
        assert resp.status_code == 302
        assert (await client.get("/me")).json() == {}
