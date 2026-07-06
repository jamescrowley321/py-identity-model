from unittest.mock import AsyncMock

from fastapi import Depends, FastAPI
import httpx
import pytest

from fastapi_identity_model import TokenValidationMiddleware, get_claims
import fastapi_identity_model.middleware as mw
from py_identity_model import DiscoveryException, TokenValidationException


pytestmark = pytest.mark.unit

DISCOVERY_URL = "https://op/.well-known/openid-configuration"


def _app(monkeypatch, validate) -> FastAPI:
    monkeypatch.setattr(mw, "validate_token", validate)
    app = FastAPI()
    app.add_middleware(
        TokenValidationMiddleware,
        discovery_url=DISCOVERY_URL,
        audience="cid",
        excluded_paths=["/health"],
    )

    @app.get("/health")
    async def health():
        return {"ok": True}

    @app.get("/me")
    async def me(claims: dict = Depends(get_claims)):
        return claims

    return app


def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    )


async def test_excluded_path_skips_validation(monkeypatch):
    async with _client(_app(monkeypatch, AsyncMock())) as client:
        assert (await client.get("/health")).status_code == 200


async def test_missing_authorization_header(monkeypatch):
    async with _client(_app(monkeypatch, AsyncMock())) as client:
        resp = await client.get("/me")
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Missing Authorization header"


async def test_malformed_authorization_header(monkeypatch):
    async with _client(_app(monkeypatch, AsyncMock())) as client:
        resp = await client.get("/me", headers={"Authorization": "Token abc"})
    assert resp.status_code == 401
    assert "Invalid Authorization header format" in resp.json()["detail"]


async def test_valid_token_attaches_claims(monkeypatch):
    claims = {"sub": "user-1", "scope": "openid"}
    async with _client(_app(monkeypatch, AsyncMock(return_value=claims))) as client:
        resp = await client.get("/me", headers={"Authorization": "Bearer good"})
    assert resp.status_code == 200
    assert resp.json() == claims


async def test_invalid_token_returns_401(monkeypatch):
    validate = AsyncMock(side_effect=TokenValidationException("bad sig"))
    async with _client(_app(monkeypatch, validate)) as client:
        resp = await client.get("/me", headers={"Authorization": "Bearer bad"})
    assert resp.status_code == 401
    assert "Token validation failed" in resp.json()["detail"]


async def test_unexpected_error_returns_500(monkeypatch):
    validate = AsyncMock(side_effect=RuntimeError("boom"))
    async with _client(_app(monkeypatch, validate)) as client:
        resp = await client.get("/me", headers={"Authorization": "Bearer x"})
    assert resp.status_code == 500
    assert resp.json()["detail"] == "Internal server error during authentication"


async def test_network_error_returns_503(monkeypatch):
    validate = AsyncMock(side_effect=DiscoveryException("provider unreachable"))
    async with _client(_app(monkeypatch, validate)) as client:
        resp = await client.get("/me", headers={"Authorization": "Bearer x"})
    assert resp.status_code == 503


async def test_id_token_rejected_as_access_token(monkeypatch):
    # A token bearing an ID-token-only claim (nonce) must not authenticate at
    # the resource server even though its aud matches the client_id.
    claims = {"sub": "user-1", "aud": "cid", "nonce": "n-123"}
    async with _client(_app(monkeypatch, AsyncMock(return_value=claims))) as client:
        resp = await client.get("/me", headers={"Authorization": "Bearer idtok"})
    assert resp.status_code == 401
    assert "ID token" in resp.json()["detail"]


async def test_excluded_subpath_skips_validation(monkeypatch):
    # A subpath of an excluded entry is also excluded: it reaches routing
    # (404, no such route) rather than being blocked with a 401.
    async with _client(_app(monkeypatch, AsyncMock())) as client:
        resp = await client.get("/health/live")
    assert resp.status_code != 401


async def test_options_preflight_passes_through(monkeypatch):
    async with _client(_app(monkeypatch, AsyncMock())) as client:
        resp = await client.options("/me")
    assert resp.status_code != 401


def test_audience_is_required():
    with pytest.raises(ValueError, match="audience"):
        TokenValidationMiddleware(FastAPI(), discovery_url=DISCOVERY_URL)


def test_explicit_empty_excluded_paths_excludes_nothing():
    mw_obj = TokenValidationMiddleware(
        FastAPI(), discovery_url=DISCOVERY_URL, audience="cid", excluded_paths=[]
    )
    assert mw_obj.excluded_paths == []
    assert mw_obj._is_excluded("/docs") is False


def test_root_excluded_path_is_not_a_catch_all():
    # A "/" entry must match only the root, not every path via subpath prefix.
    mw_obj = TokenValidationMiddleware(
        FastAPI(),
        discovery_url=DISCOVERY_URL,
        audience="cid",
        excluded_paths=["/", "/docs"],
    )
    assert mw_obj._is_excluded("/") is True
    assert mw_obj._is_excluded("/api/me") is False
    assert mw_obj._is_excluded("/docs") is True
    assert mw_obj._is_excluded("/docs/oauth2-redirect") is True
