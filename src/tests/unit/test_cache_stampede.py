"""
Security tests for cache stampede prevention (#378).

Verifies that concurrent cache misses (TTL expiry) result in a single HTTP
fetch rather than N parallel fetches (thundering herd).
"""

import asyncio
import threading
import time

import httpx
import pytest
import respx

from py_identity_model.aio import token_validation as aio_tv
from py_identity_model.aio.token_validation import (
    _get_cached_jwks as async_get_cached_jwks,
)
from py_identity_model.aio.token_validation import (
    _get_disco_response as async_get_disco_response,
)
from py_identity_model.aio.token_validation import (
    _refresh_jwks as async_refresh_jwks,
)
from py_identity_model.aio.token_validation import (
    clear_discovery_cache as async_clear_discovery_cache,
)
from py_identity_model.aio.token_validation import (
    clear_jwks_cache as async_clear_jwks_cache,
)
from py_identity_model.core.jwks_cache import DiscoCacheEntry, JwksCacheEntry
from py_identity_model.sync import token_validation as sync_tv
from py_identity_model.sync.token_validation import (
    _get_cached_jwks,
    _get_disco_response,
    _refresh_jwks,
    clear_discovery_cache,
    clear_jwks_cache,
)

from .token_validation_helpers import (
    DISCO_RESPONSE_WITH_JWKS,
    generate_rsa_keypair,
)


DISCO_URL = "https://example.com/.well-known/openid-configuration"
JWKS_URL = "https://example.com/jwks"

# Expected fetch counts: 1 initial prime + 1 single-flight refresh after expiry
FETCH_AFTER_EXPIRY = 2


@pytest.fixture(autouse=True)
def _clear_caches():
    """Clear all caches between tests."""
    clear_discovery_cache()
    clear_jwks_cache()
    async_clear_discovery_cache()
    async_clear_jwks_cache()
    yield
    clear_discovery_cache()
    clear_jwks_cache()
    async_clear_discovery_cache()
    async_clear_jwks_cache()


class TestSyncDiscoCacheStampede:
    """Verify sync discovery cache prevents thundering herd on TTL expiry."""

    @respx.mock
    def test_disco_cache_stampede_blocked(self):
        """Multiple threads hitting expired cache produce only 1 HTTP fetch."""
        disco_route = respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )

        barrier = threading.Barrier(5, timeout=5)
        results: list[object] = [None] * 5
        errors: list[Exception | None] = [None] * 5

        def worker(idx: int) -> None:
            try:
                barrier.wait()
                results[idx] = _get_disco_response(DISCO_URL)
            except Exception as exc:
                errors[idx] = exc

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        for err in errors:
            assert err is None, f"Thread raised: {err}"

        # All 5 threads should have gotten a result
        assert all(r is not None for r in results)
        # Only 1 HTTP fetch should have occurred (single-flight)
        assert disco_route.call_count == 1


class TestSyncJwksCacheStampede:
    """Verify sync JWKS cache prevents thundering herd on TTL expiry."""

    @respx.mock
    def test_jwks_cache_stampede_blocked(self):
        """Multiple threads hitting expired JWKS cache produce only 1 HTTP fetch."""
        key_dict, _ = generate_rsa_keypair()
        jwks_route = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [key_dict]})
        )

        barrier = threading.Barrier(5, timeout=5)
        results: list[object] = [None] * 5
        errors: list[Exception | None] = [None] * 5

        def worker(idx: int) -> None:
            try:
                barrier.wait()
                results[idx] = _get_cached_jwks(JWKS_URL)
            except Exception as exc:
                errors[idx] = exc

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        for err in errors:
            assert err is None, f"Thread raised: {err}"

        assert all(r is not None for r in results)
        assert jwks_route.call_count == 1


class TestSyncStampedeAfterExpiry:
    """Verify stampede prevention after TTL expiry."""

    @respx.mock
    def test_jwks_stampede_after_expiry_blocked(self):
        """After TTL expires, concurrent fetches produce only 1 new HTTP request."""
        key_dict, _ = generate_rsa_keypair()
        jwks_route = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [key_dict]})
        )

        # Prime cache, then expire it by backdating cached_at
        _get_cached_jwks(JWKS_URL)
        assert jwks_route.call_count == 1

        # Expire the entry by setting cached_at far in the past
        sync_tv._jwks_cache[JWKS_URL] = JwksCacheEntry(
            response=sync_tv._jwks_cache[JWKS_URL].response,
            cached_at=time.time() - 86401,
            ttl=86400.0,
        )

        barrier = threading.Barrier(5, timeout=5)
        errors: list[Exception | None] = [None] * 5

        def worker(idx: int) -> None:
            try:
                barrier.wait()
                _get_cached_jwks(JWKS_URL)
            except Exception as exc:
                errors[idx] = exc

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        for err in errors:
            assert err is None, f"Thread raised: {err}"

        # 1 initial + 1 refresh (NOT 1 + 5)
        assert jwks_route.call_count == FETCH_AFTER_EXPIRY

    @respx.mock
    def test_disco_stampede_after_expiry_blocked(self):
        """After disco TTL expires, concurrent fetches produce only 1 new request."""
        disco_route = respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )

        # Prime cache, then expire it
        _get_disco_response(DISCO_URL)
        assert disco_route.call_count == 1

        cache_key = (DISCO_URL, True)
        sync_tv._disco_cache[cache_key] = DiscoCacheEntry(
            response=sync_tv._disco_cache[cache_key].response,
            cached_at=time.time() - 3601,
            ttl=3600.0,
        )

        barrier = threading.Barrier(5, timeout=5)
        errors: list[Exception | None] = [None] * 5

        def worker(idx: int) -> None:
            try:
                barrier.wait()
                _get_disco_response(DISCO_URL)
            except Exception as exc:
                errors[idx] = exc

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        for err in errors:
            assert err is None, f"Thread raised: {err}"

        assert disco_route.call_count == FETCH_AFTER_EXPIRY


class TestAsyncDiscoCacheStampede:
    """Verify async discovery cache prevents thundering herd on TTL expiry."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_disco_cache_stampede_blocked_async(self):
        """Multiple coroutines hitting expired cache produce only 1 HTTP fetch."""
        disco_route = respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )

        results = await asyncio.gather(
            *[async_get_disco_response(DISCO_URL) for _ in range(5)]
        )

        assert all(r is not None for r in results)
        assert disco_route.call_count == 1


class TestAsyncJwksCacheStampede:
    """Verify async JWKS cache prevents thundering herd on TTL expiry."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_jwks_cache_stampede_blocked_async(self):
        """Multiple coroutines hitting expired JWKS cache produce only 1 HTTP fetch."""
        key_dict, _ = generate_rsa_keypair()
        jwks_route = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [key_dict]})
        )

        results = await asyncio.gather(
            *[async_get_cached_jwks(JWKS_URL) for _ in range(5)]
        )

        assert all(r is not None for r in results)
        assert jwks_route.call_count == 1


class TestAsyncStampedeAfterExpiry:
    """Verify async stampede prevention after TTL expiry."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_jwks_stampede_after_expiry_blocked_async(self):
        """After TTL expires, concurrent async fetches produce only 1 new request."""
        key_dict, _ = generate_rsa_keypair()
        jwks_route = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [key_dict]})
        )

        # Prime cache
        await async_get_cached_jwks(JWKS_URL)
        assert jwks_route.call_count == 1

        # Expire the entry
        aio_tv._jwks_cache[JWKS_URL] = JwksCacheEntry(
            response=aio_tv._jwks_cache[JWKS_URL].response,
            cached_at=time.time() - 86401,
            ttl=86400.0,
        )

        results = await asyncio.gather(
            *[async_get_cached_jwks(JWKS_URL) for _ in range(5)]
        )

        assert all(r is not None for r in results)
        # 1 initial + 1 refresh (NOT 1 + 5)
        assert jwks_route.call_count == FETCH_AFTER_EXPIRY

    @pytest.mark.asyncio
    @respx.mock
    async def test_disco_stampede_after_expiry_blocked_async(self):
        """After disco TTL expires, concurrent async fetches produce only 1 new request."""
        disco_route = respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )

        # Prime cache
        await async_get_disco_response(DISCO_URL)
        assert disco_route.call_count == 1

        # Expire the entry
        cache_key = (DISCO_URL, True)
        aio_tv._disco_cache[cache_key] = DiscoCacheEntry(
            response=aio_tv._disco_cache[cache_key].response,
            cached_at=time.time() - 3601,
            ttl=3600.0,
        )

        results = await asyncio.gather(
            *[async_get_disco_response(DISCO_URL) for _ in range(5)]
        )

        assert all(r is not None for r in results)
        assert disco_route.call_count == FETCH_AFTER_EXPIRY


class TestSyncRefreshJwksFreshnessGuard:
    """Verify _refresh_jwks skips fetch when another thread already refreshed."""

    @respx.mock
    def test_refresh_skips_fetch_when_already_fresh(self):
        """If cache was refreshed while waiting on lock, return cached entry."""
        key_dict, _ = generate_rsa_keypair()
        jwks_route = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [key_dict]})
        )

        # Prime the cache
        _get_cached_jwks(JWKS_URL)
        assert jwks_route.call_count == 1

        # Manually set cached_at to a future time to simulate another thread
        # having just refreshed the cache
        entry = sync_tv._jwks_cache[JWKS_URL]
        sync_tv._jwks_cache[JWKS_URL] = JwksCacheEntry(
            response=entry.response,
            cached_at=time.time() + 100,
            ttl=entry.ttl,
        )

        # _refresh_jwks should see the fresh entry and skip the HTTP fetch
        result = _refresh_jwks(JWKS_URL)
        assert result is not None
        # No new fetch — still just the 1 from priming
        assert jwks_route.call_count == 1

    @respx.mock
    def test_refresh_fetches_when_cache_stale(self):
        """Normal refresh path: fetch when cache is stale."""
        key_dict, _ = generate_rsa_keypair()
        jwks_route = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [key_dict]})
        )

        # Prime the cache
        _get_cached_jwks(JWKS_URL)
        assert jwks_route.call_count == 1

        # Call _refresh_jwks — cached_at is in the past relative to request_time
        result = _refresh_jwks(JWKS_URL)
        assert result is not None
        assert jwks_route.call_count == FETCH_AFTER_EXPIRY


class TestAsyncRefreshJwksFreshnessGuard:
    """Verify async _refresh_jwks skips fetch when another coroutine already refreshed."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_refresh_skips_fetch_when_already_fresh_async(self):
        """If cache was refreshed while waiting on lock, return cached entry."""
        key_dict, _ = generate_rsa_keypair()
        jwks_route = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [key_dict]})
        )

        # Prime the cache
        await async_get_cached_jwks(JWKS_URL)
        assert jwks_route.call_count == 1

        # Set cached_at to future time to simulate another coroutine refresh
        entry = aio_tv._jwks_cache[JWKS_URL]
        aio_tv._jwks_cache[JWKS_URL] = JwksCacheEntry(
            response=entry.response,
            cached_at=time.time() + 100,
            ttl=entry.ttl,
        )

        result = await async_refresh_jwks(JWKS_URL)
        assert result is not None
        assert jwks_route.call_count == 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_refresh_fetches_when_cache_stale_async(self):
        """Normal refresh path: fetch when cache is stale."""
        key_dict, _ = generate_rsa_keypair()
        jwks_route = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [key_dict]})
        )

        await async_get_cached_jwks(JWKS_URL)
        assert jwks_route.call_count == 1

        result = await async_refresh_jwks(JWKS_URL)
        assert result is not None
        assert jwks_route.call_count == FETCH_AFTER_EXPIRY
