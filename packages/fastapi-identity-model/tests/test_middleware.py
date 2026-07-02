from unittest.mock import AsyncMock

from fastapi import Depends, FastAPI
import httpx
import pytest

from fastapi_identity_model import TokenValidationMiddleware, get_claims
import fastapi_identity_model.middleware as mw
from py_identity_model import TokenValidationException


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
