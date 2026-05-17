"""
Proves the cache uses per-URI locks rather than a single global lock that
serializes upstream fetches across unrelated issuers.

Pre-fix: a single ``threading.Lock`` (sync) / ``asyncio.Lock`` (async) was
held *across* the upstream HTTP fetch in ``_get_cached_jwks`` /
``_get_disco_response`` / ``_refresh_jwks``. A request fetching JWKS from
``https://idp-a/jwks`` blocked every other request fetching JWKS from any
*other* address until the first request's network round-trip completed.

In a multi-tenant FastAPI app with multiple issuers and a slow upstream
(or one with a momentary glitch) this serialized the entire process on the
slowest fetch, regardless of which issuer the slowness affected.

Post-fix: the cache uses cache-aside with per-URI lock striping (32
stripes). Fetches for distinct URIs run in parallel; only fetches for the
*same* URI serialize, which is the actual single-flight contract.

The tests use a slow handler (sleep) to prove parallelism by wall-clock
total time. We allow a slack margin for scheduling jitter, but the
serialized vs. parallel times differ by ~2x — well outside any noise.
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
import threading
import time

import httpx
import pytest
import respx

from py_identity_model.aio.token_validation import (
    _get_cached_jwks as async_get_cached_jwks,
)
from py_identity_model.aio.token_validation import (
    clear_discovery_cache as async_clear_discovery_cache,
)
from py_identity_model.aio.token_validation import (
    clear_jwks_cache as async_clear_jwks_cache,
)
from py_identity_model.sync.token_validation import (
    _get_cached_jwks,
    clear_discovery_cache,
    clear_jwks_cache,
)

from .token_validation_helpers import generate_rsa_keypair


@pytest.fixture(autouse=True)
def _clear_caches():
    clear_discovery_cache()
    clear_jwks_cache()
    async_clear_discovery_cache()
    async_clear_jwks_cache()
    yield
    clear_discovery_cache()
    clear_jwks_cache()
    async_clear_discovery_cache()
    async_clear_jwks_cache()


# Per-fetch sleep. Long enough that serialized vs parallel differ by a
# clear margin even with thread scheduling jitter, short enough to keep
# the suite fast.
FETCH_DELAY_SECONDS = 0.4
# Total elapsed must be < 2x delay (parallel) and clearly < the serial
# floor of 2x delay. The threshold lets one full delay fit but rejects two.
PARALLEL_MAX_ELAPSED = FETCH_DELAY_SECONDS * 1.6


def _make_jwks_payload() -> dict:
    key_dict, _ = generate_rsa_keypair()
    return {"keys": [key_dict]}


def _build_slow_handler(payload: dict):
    """Return a respx side_effect that sleeps before responding."""

    def handler(_request: httpx.Request) -> httpx.Response:
        time.sleep(FETCH_DELAY_SECONDS)
        return httpx.Response(200, json=payload)

    return handler


def _build_slow_async_handler(payload: dict):
    async def handler(_request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(FETCH_DELAY_SECONDS)
        return httpx.Response(200, json=payload)

    return handler


# ============================================================================
# Sync: distinct URIs fetch in parallel (no global serialization)
# ============================================================================


class TestSyncDistinctUrisParallelizeFetches:
    @respx.mock
    def test_two_distinct_uris_fetch_in_parallel(self):
        url_a = "https://op-a.example/jwks"
        url_b = "https://op-b.example/jwks"
        respx.get(url_a).mock(side_effect=_build_slow_handler(_make_jwks_payload()))
        respx.get(url_b).mock(side_effect=_build_slow_handler(_make_jwks_payload()))

        # Sync the start of both threads via a barrier so we measure
        # actual concurrent fetch behavior, not staggered start jitter.
        barrier = threading.Barrier(2)

        def fetch(url: str) -> None:
            barrier.wait()
            _get_cached_jwks(url)

        start = time.monotonic()
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(fetch, url_a), pool.submit(fetch, url_b)]
            for f in futures:
                f.result()
        elapsed = time.monotonic() - start

        # Pre-fix would have serialized to ~2x FETCH_DELAY_SECONDS.
        assert elapsed < PARALLEL_MAX_ELAPSED, (
            f"Distinct-URI fetches serialized: elapsed {elapsed:.2f}s, "
            f"expected < {PARALLEL_MAX_ELAPSED:.2f}s. The cache must use "
            "per-URI locking, not a single global lock."
        )

    @respx.mock
    def test_same_uri_still_single_flight(self):
        """The fix must not regress single-flight semantics: two concurrent
        requests for the *same* URI must coalesce into one upstream fetch."""
        url = "https://op-shared.example/jwks"
        route = respx.get(url).mock(
            side_effect=_build_slow_handler(_make_jwks_payload())
        )

        barrier = threading.Barrier(5)

        def fetch() -> None:
            barrier.wait()
            _get_cached_jwks(url)

        with ThreadPoolExecutor(max_workers=5) as pool:
            futures = [pool.submit(fetch) for _ in range(5)]
            for f in futures:
                f.result()

        # Single-flight: 5 concurrent same-URI requests → 1 upstream fetch.
        assert route.call_count == 1


# ============================================================================
# Async: distinct URIs fetch in parallel
# ============================================================================


class TestAsyncDistinctUrisParallelizeFetches:
    @pytest.mark.asyncio
    @respx.mock
    async def test_two_distinct_uris_fetch_in_parallel_async(self):
        url_a = "https://op-a.example/jwks"
        url_b = "https://op-b.example/jwks"
        respx.get(url_a).mock(
            side_effect=_build_slow_async_handler(_make_jwks_payload())
        )
        respx.get(url_b).mock(
            side_effect=_build_slow_async_handler(_make_jwks_payload())
        )

        start = time.monotonic()
        await asyncio.gather(
            async_get_cached_jwks(url_a),
            async_get_cached_jwks(url_b),
        )
        elapsed = time.monotonic() - start

        assert elapsed < PARALLEL_MAX_ELAPSED, (
            f"Distinct-URI async fetches serialized: elapsed {elapsed:.2f}s, "
            f"expected < {PARALLEL_MAX_ELAPSED:.2f}s. The async cache must "
            "use per-URI locks, not a single asyncio.Lock held across await."
        )

    @pytest.mark.asyncio
    @respx.mock
    async def test_same_uri_still_single_flight_async(self):
        url = "https://op-shared.example/jwks"
        route = respx.get(url).mock(
            side_effect=_build_slow_async_handler(_make_jwks_payload())
        )

        await asyncio.gather(*(async_get_cached_jwks(url) for _ in range(5)))
        assert route.call_count == 1
