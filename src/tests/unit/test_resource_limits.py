"""Tests for resource limits and concurrency fixes (Batch 5).

Covers:
- #353: JWKS response size limit
- #357: Async cleanup lock race
"""

import asyncio
import json
from typing import ClassVar

import httpx
import pytest

from py_identity_model.aio.http_client import (
    _cleanup_lock,
    _reset_async_http_client,
    close_async_http_client,
    get_async_http_client,
)
from py_identity_model.core.http_utils import DEFAULT_MAX_JWKS_SIZE
from py_identity_model.core.response_processors import parse_jwks_response


# ============================================================================
# #353 — JWKS response size limit
# ============================================================================


class TestJwksSizeLimit:
    """Verify JWKS responses are rejected when too large."""

    _SMALL_JWKS: ClassVar[dict] = {
        "keys": [{"kty": "RSA", "kid": "k1", "n": "n", "e": "AQAB"}]
    }

    def test_accepts_small_response(self):
        response = httpx.Response(
            200,
            json=self._SMALL_JWKS,
            headers={"Content-Type": "application/json"},
        )
        result = parse_jwks_response(response)
        assert result.is_successful is True

    def test_rejects_large_content_length(self):
        response = httpx.Response(
            200,
            content=b'{"keys": []}',
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(DEFAULT_MAX_JWKS_SIZE + 1),
            },
        )
        result = parse_jwks_response(response)
        assert result.is_successful is False
        assert result.error is not None
        assert "too large" in result.error

    def test_rejects_large_body(self, monkeypatch):
        """Body larger than limit is rejected even without Content-Length."""
        monkeypatch.setenv("MAX_JWKS_SIZE", "100")
        big_body = json.dumps({"keys": [{"kty": "RSA", "n": "x" * 200, "e": "AQAB"}]})
        response = httpx.Response(
            200,
            content=big_body.encode(),
            headers={"Content-Type": "application/json"},
        )
        result = parse_jwks_response(response)
        assert result.is_successful is False
        assert result.error is not None
        assert "too large" in result.error

    def test_respects_env_var_override(self, monkeypatch):
        monkeypatch.setenv("MAX_JWKS_SIZE", "50")
        response = httpx.Response(
            200,
            content=b'{"keys": [{"kty": "RSA", "n": "long_value", "e": "AQAB"}]}',
            headers={"Content-Type": "application/json"},
        )
        result = parse_jwks_response(response)
        assert result.is_successful is False
        assert result.error is not None
        assert "too large" in result.error

    def test_non_success_skips_size_check(self):
        """Non-2xx responses report HTTP error, not size."""
        response = httpx.Response(
            500,
            content=b"x" * (DEFAULT_MAX_JWKS_SIZE + 1),
        )
        result = parse_jwks_response(response)
        assert result.is_successful is False
        assert result.error is not None
        assert "500" in result.error


# ============================================================================
# #357 — Async cleanup lock race
# ============================================================================


class TestAsyncCleanupLock:
    """Verify the async cleanup lock is eagerly initialized."""

    def test_cleanup_lock_is_module_level(self):
        """The cleanup lock should exist at module level, not lazily created."""
        assert isinstance(_cleanup_lock, asyncio.Lock)

    @pytest.mark.asyncio
    async def test_concurrent_close_does_not_race(self):
        """Multiple concurrent close calls should not raise."""
        _reset_async_http_client()
        _ = get_async_http_client()

        # Close concurrently from multiple coroutines
        await asyncio.gather(
            close_async_http_client(),
            close_async_http_client(),
            close_async_http_client(),
        )
        # No error = no race

    @pytest.mark.asyncio
    async def test_close_then_recreate(self):
        """Client can be recreated after closing."""
        _reset_async_http_client()
        client1 = get_async_http_client()
        await close_async_http_client()
        client2 = get_async_http_client()
        assert client2 is not client1
        _reset_async_http_client()
