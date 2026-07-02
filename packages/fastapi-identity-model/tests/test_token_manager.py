from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from fastapi_identity_model import TokenManager
import fastapi_identity_model.token_manager as tm_mod
from py_identity_model import PyIdentityModelException


pytestmark = pytest.mark.unit


def _disco(ok=True, token_endpoint="https://op/token", error=None):
    return SimpleNamespace(is_successful=ok, token_endpoint=token_endpoint, error=error)


def _refresh_response(ok=True, token=None, error=None):
    return SimpleNamespace(is_successful=ok, token=token, error=error)


async def test_returns_cached_token_when_not_expired():
    tm = TokenManager("d", "cid")
    tm.set_tokens(access_token="cached", refresh_token="r", expires_in=3600)
    assert await tm.get_access_token() == "cached"
    assert tm.access_token == "cached"
    assert tm.refresh_token == "r"


async def test_no_expiry_is_never_expired():
    tm = TokenManager("d", "cid")
    tm.set_tokens(access_token="a")
    assert tm.is_token_expired() is False


async def test_refresh_when_expired(monkeypatch):
    monkeypatch.setattr(
        tm_mod, "get_discovery_document", AsyncMock(return_value=_disco())
    )
    monkeypatch.setattr(
        tm_mod,
        "refresh_token",
        AsyncMock(
            return_value=_refresh_response(
                token={
                    "access_token": "fresh",
                    "refresh_token": "r2",
                    "expires_in": 3600,
                }
            )
        ),
    )
    tm = TokenManager("d", "cid", "secret")
    tm.set_tokens(access_token="stale", refresh_token="r1", expires_in=-10)
    assert await tm.get_access_token() == "fresh"
    assert tm.refresh_token == "r2"


async def test_refresh_keeps_old_refresh_token_when_none_returned(monkeypatch):
    monkeypatch.setattr(
        tm_mod, "get_discovery_document", AsyncMock(return_value=_disco())
    )
    monkeypatch.setattr(
        tm_mod,
        "refresh_token",
        AsyncMock(return_value=_refresh_response(token={"access_token": "fresh"})),
    )
    tm = TokenManager("d", "cid")
    tm.set_tokens(access_token="stale", refresh_token="keep", expires_in=-10)
    await tm.get_access_token()
    assert tm.refresh_token == "keep"


async def test_no_refresh_token_raises():
    tm = TokenManager("d", "cid")
    tm.set_tokens(access_token="stale", expires_in=-10)
    with pytest.raises(PyIdentityModelException, match="no refresh token"):
        await tm.get_access_token()


async def test_discovery_failure_raises(monkeypatch):
    monkeypatch.setattr(
        tm_mod,
        "get_discovery_document",
        AsyncMock(return_value=_disco(ok=False, token_endpoint=None, error="down")),
    )
    tm = TokenManager("d", "cid")
    tm.set_tokens(access_token="stale", refresh_token="r", expires_in=-10)
    with pytest.raises(PyIdentityModelException, match="Discovery failed"):
        await tm.get_access_token()


async def test_refresh_grant_failure_raises(monkeypatch):
    monkeypatch.setattr(
        tm_mod, "get_discovery_document", AsyncMock(return_value=_disco())
    )
    monkeypatch.setattr(
        tm_mod,
        "refresh_token",
        AsyncMock(return_value=_refresh_response(ok=False, error="invalid_grant")),
    )
    tm = TokenManager("d", "cid")
    tm.set_tokens(access_token="stale", refresh_token="r", expires_in=-10)
    with pytest.raises(PyIdentityModelException, match="Token refresh failed"):
        await tm.get_access_token()


async def test_refresh_without_access_token_raises(monkeypatch):
    monkeypatch.setattr(
        tm_mod, "get_discovery_document", AsyncMock(return_value=_disco())
    )
    monkeypatch.setattr(
        tm_mod,
        "refresh_token",
        AsyncMock(return_value=_refresh_response(token={"refresh_token": "r2"})),
    )
    tm = TokenManager("d", "cid")
    tm.set_tokens(access_token="stale", refresh_token="r", expires_in=-10)
    with pytest.raises(PyIdentityModelException, match="no access token"):
        await tm.get_access_token()
