"""
Tests for HTTP cache header semantics in JWKS and discovery caches.

Covers three correctness fixes:
1. Failed JWKS/discovery responses must not be cached (a transient 5xx or
   network error would otherwise poison the cache for up to 24h).
2. ``Cache-Control: no-store`` must not be cached at all (RFC 7234 §5.2.2.5).
3. ``Cache-Control: no-cache`` must always re-fetch (RFC 7234 §5.2.2.4) —
   simplest correct behavior is to skip caching.
"""

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
    clear_discovery_cache as async_clear_discovery_cache,
)
from py_identity_model.aio.token_validation import (
    clear_jwks_cache as async_clear_jwks_cache,
)
from py_identity_model.sync import token_validation as sync_tv
from py_identity_model.sync.token_validation import (
    _get_cached_jwks,
    _get_disco_response,
    clear_discovery_cache,
    clear_jwks_cache,
)

from .token_validation_helpers import (
    DISCO_RESPONSE_WITH_JWKS,
    generate_rsa_keypair,
)


DISCO_URL = "https://example.com/.well-known/openid-configuration"
JWKS_URL = "https://example.com/jwks"


@pytest.fixture(autouse=True)
async def _clear_caches():
    clear_discovery_cache()
    clear_jwks_cache()
    await async_clear_discovery_cache()
    await async_clear_jwks_cache()
    yield
    clear_discovery_cache()
    clear_jwks_cache()
    await async_clear_discovery_cache()
    await async_clear_jwks_cache()


# ============================================================================
# Failed responses must not be cached
# ============================================================================


class TestSyncFailedResponseNotCached:
    @respx.mock
    def test_jwks_failure_then_success_refetches(self):
        """A transient JWKS failure must not poison the cache.

        Uses 404 to bypass the HTTP client's built-in 5xx retry behavior
        and isolate the cache-layer policy: ``is_successful=False`` must
        never be cached, regardless of the upstream status code.
        """
        key_dict = generate_rsa_keypair()[0]
        call_log: list[int] = []

        def handler(_request: httpx.Request) -> httpx.Response:
            call_log.append(1)
            if len(call_log) == 1:
                return httpx.Response(404, text="not found")
            return httpx.Response(200, json={"keys": [key_dict]})

        respx.get(JWKS_URL).mock(side_effect=handler)

        failed = _get_cached_jwks(JWKS_URL)
        assert failed.is_successful is False
        assert JWKS_URL not in sync_tv._jwks_cache

        # Next call must re-fetch and succeed.
        success = _get_cached_jwks(JWKS_URL)
        assert success.is_successful is True
        assert JWKS_URL in sync_tv._jwks_cache
        assert len(call_log) == 2  # noqa: PLR2004

    @respx.mock
    def test_disco_failure_then_success_refetches(self):
        """A transient discovery failure must not poison the cache."""
        call_log: list[int] = []

        def handler(_request: httpx.Request) -> httpx.Response:
            call_log.append(1)
            if len(call_log) == 1:
                return httpx.Response(404, text="not found")
            return httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)

        respx.get(DISCO_URL).mock(side_effect=handler)

        failed = _get_disco_response(DISCO_URL)
        assert failed.is_successful is False
        assert (DISCO_URL, True) not in sync_tv._disco_cache

        success = _get_disco_response(DISCO_URL)
        assert success.is_successful is True
        assert (DISCO_URL, True) in sync_tv._disco_cache
        assert len(call_log) == 2  # noqa: PLR2004


class TestAsyncFailedResponseNotCached:
    @pytest.mark.asyncio
    @respx.mock
    async def test_jwks_failure_then_success_refetches_async(self):
        key_dict = generate_rsa_keypair()[0]
        call_log: list[int] = []

        def handler(_request: httpx.Request) -> httpx.Response:
            call_log.append(1)
            if len(call_log) == 1:
                return httpx.Response(404, text="not found")
            return httpx.Response(200, json={"keys": [key_dict]})

        respx.get(JWKS_URL).mock(side_effect=handler)

        failed = await async_get_cached_jwks(JWKS_URL)
        assert failed.is_successful is False
        assert JWKS_URL not in aio_tv._jwks_cache

        success = await async_get_cached_jwks(JWKS_URL)
        assert success.is_successful is True
        assert JWKS_URL in aio_tv._jwks_cache
        assert len(call_log) == 2  # noqa: PLR2004

    @pytest.mark.asyncio
    @respx.mock
    async def test_disco_failure_then_success_refetches_async(self):
        call_log: list[int] = []

        def handler(_request: httpx.Request) -> httpx.Response:
            call_log.append(1)
            if len(call_log) == 1:
                return httpx.Response(404, text="not found")
            return httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)

        respx.get(DISCO_URL).mock(side_effect=handler)

        failed = await async_get_disco_response(DISCO_URL)
        assert failed.is_successful is False
        assert (DISCO_URL, True) not in aio_tv._disco_cache

        success = await async_get_disco_response(DISCO_URL)
        assert success.is_successful is True
        assert (DISCO_URL, True) in aio_tv._disco_cache
        assert len(call_log) == 2  # noqa: PLR2004


# ============================================================================
# Cache-Control: no-store — never cached
# ============================================================================


class TestSyncNoStoreNotCached:
    @respx.mock
    def test_jwks_no_store_skips_cache(self):
        """no-store responses are returned but not cached, even with max-age."""
        key_dict = generate_rsa_keypair()[0]
        respx.get(JWKS_URL).mock(
            return_value=httpx.Response(
                200,
                json={"keys": [key_dict]},
                headers={"Cache-Control": "no-store, max-age=600"},
            )
        )

        response = _get_cached_jwks(JWKS_URL)
        assert response.is_successful is True
        assert response.keys is not None
        assert JWKS_URL not in sync_tv._jwks_cache

    @respx.mock
    def test_disco_no_store_skips_cache(self):
        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(
                200,
                json=DISCO_RESPONSE_WITH_JWKS,
                headers={"Cache-Control": "no-store"},
            )
        )

        response = _get_disco_response(DISCO_URL)
        assert response.is_successful is True
        assert (DISCO_URL, True) not in sync_tv._disco_cache


class TestAsyncNoStoreNotCached:
    @pytest.mark.asyncio
    @respx.mock
    async def test_jwks_no_store_skips_cache_async(self):
        key_dict = generate_rsa_keypair()[0]
        respx.get(JWKS_URL).mock(
            return_value=httpx.Response(
                200,
                json={"keys": [key_dict]},
                headers={"Cache-Control": "no-store, max-age=600"},
            )
        )

        response = await async_get_cached_jwks(JWKS_URL)
        assert response.is_successful is True
        assert JWKS_URL not in aio_tv._jwks_cache

    @pytest.mark.asyncio
    @respx.mock
    async def test_disco_no_store_skips_cache_async(self):
        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(
                200,
                json=DISCO_RESPONSE_WITH_JWKS,
                headers={"Cache-Control": "no-store"},
            )
        )

        response = await async_get_disco_response(DISCO_URL)
        assert response.is_successful is True
        assert (DISCO_URL, True) not in aio_tv._disco_cache


# ============================================================================
# Cache-Control: no-cache — always re-fetch
# ============================================================================


class TestSyncNoCacheRefetched:
    @respx.mock
    def test_jwks_no_cache_refetches_each_call(self):
        """no-cache responses always re-fetch (we don't store them)."""
        key_dict = generate_rsa_keypair()[0]
        jwks_route = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(
                200,
                json={"keys": [key_dict]},
                headers={"Cache-Control": "no-cache, max-age=600"},
            )
        )

        for _ in range(3):
            response = _get_cached_jwks(JWKS_URL)
            assert response.is_successful is True

        assert JWKS_URL not in sync_tv._jwks_cache
        assert jwks_route.call_count == 3  # noqa: PLR2004

    @respx.mock
    def test_disco_no_cache_refetches_each_call(self):
        disco_route = respx.get(DISCO_URL).mock(
            return_value=httpx.Response(
                200,
                json=DISCO_RESPONSE_WITH_JWKS,
                headers={"Cache-Control": "no-cache"},
            )
        )

        for _ in range(3):
            response = _get_disco_response(DISCO_URL)
            assert response.is_successful is True

        assert (DISCO_URL, True) not in sync_tv._disco_cache
        assert disco_route.call_count == 3  # noqa: PLR2004


class TestAsyncNoCacheRefetched:
    @pytest.mark.asyncio
    @respx.mock
    async def test_jwks_no_cache_refetches_each_call_async(self):
        key_dict = generate_rsa_keypair()[0]
        jwks_route = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(
                200,
                json={"keys": [key_dict]},
                headers={"Cache-Control": "no-cache, max-age=600"},
            )
        )

        for _ in range(3):
            response = await async_get_cached_jwks(JWKS_URL)
            assert response.is_successful is True

        assert JWKS_URL not in aio_tv._jwks_cache
        assert jwks_route.call_count == 3  # noqa: PLR2004

    @pytest.mark.asyncio
    @respx.mock
    async def test_disco_no_cache_refetches_each_call_async(self):
        disco_route = respx.get(DISCO_URL).mock(
            return_value=httpx.Response(
                200,
                json=DISCO_RESPONSE_WITH_JWKS,
                headers={"Cache-Control": "no-cache"},
            )
        )

        for _ in range(3):
            await async_get_disco_response(DISCO_URL)

        assert (DISCO_URL, True) not in aio_tv._disco_cache
        assert disco_route.call_count == 3  # noqa: PLR2004


# ============================================================================
# Refresh-time invalidation: when a refresh response is uncacheable, the
# existing (potentially stale) cache entry must be POPPED, not left in place.
#
# Otherwise a key-rotation event against a provider that sends
# ``no-store``/``no-cache`` (Descope, others) leaves the stale entry live
# for the remainder of its 24h TTL. Every subsequent validation hits the
# stale entry, triggers another _refresh_jwks, and pounds the upstream JWKS
# endpoint — the exact DoS the cache exists to prevent.
# ============================================================================


def _key_with_kid(kid: str) -> dict:
    key_dict, _ = generate_rsa_keypair()
    return {**key_dict, "kid": kid}


def _kids(response) -> set[str]:
    return {k.kid for k in (response.keys or [])}


REFRESH_UNCACHEABLE_TEST_CASES = [
    pytest.param("no-store", id="no-store"),
    pytest.param("no-cache", id="no-cache"),
    pytest.param("no-store, max-age=3600", id="no-store-with-max-age"),
    pytest.param("no-cache, max-age=3600", id="no-cache-with-max-age"),
]


class TestSyncRefreshInvalidatesStaleOnUncacheable:
    @pytest.mark.parametrize("uncacheable_header", REFRESH_UNCACHEABLE_TEST_CASES)
    @respx.mock
    def test_refresh_pops_stale_entry_when_response_uncacheable(
        self, uncacheable_header: str
    ):
        old_key = _key_with_kid("old-kid")
        new_key = _key_with_kid("new-kid")
        call_log: list[int] = []

        def handler(_request: httpx.Request) -> httpx.Response:
            call_log.append(1)
            if len(call_log) == 1:
                return httpx.Response(
                    200,
                    json={"keys": [old_key]},
                    headers={"Cache-Control": "max-age=3600"},
                )
            return httpx.Response(
                200,
                json={"keys": [new_key]},
                headers={"Cache-Control": uncacheable_header},
            )

        respx.get(JWKS_URL).mock(side_effect=handler)

        primed = _get_cached_jwks(JWKS_URL)
        assert primed.is_successful is True
        assert JWKS_URL in sync_tv._jwks_cache
        assert _kids(sync_tv._jwks_cache[JWKS_URL].response) == {"old-kid"}

        refreshed = sync_tv._refresh_jwks(JWKS_URL)
        assert refreshed.is_successful is True
        # Fresh response is returned to the caller …
        assert _kids(refreshed) == {"new-kid"}
        # … but the stale entry MUST be popped, not left behind.
        assert JWKS_URL not in sync_tv._jwks_cache

    @pytest.mark.parametrize("uncacheable_header", REFRESH_UNCACHEABLE_TEST_CASES)
    @respx.mock
    def test_disco_pops_expired_entry_when_response_uncacheable(
        self, uncacheable_header: str
    ):
        """Disco has no _refresh equivalent, but expired entries still need
        the pop semantics: when re-fetching past TTL yields an uncacheable
        response, the expired entry must not linger in the dict (memory
        hygiene + cleanliness for the cache-size bound landing in a
        follow-up commit)."""
        rotated_disco = {
            **DISCO_RESPONSE_WITH_JWKS,
            "issuer": "https://rotated.example",
        }
        call_log: list[int] = []

        def handler(_request: httpx.Request) -> httpx.Response:
            call_log.append(1)
            if len(call_log) == 1:
                return httpx.Response(
                    200,
                    json=DISCO_RESPONSE_WITH_JWKS,
                    headers={"Cache-Control": "max-age=3600"},
                )
            return httpx.Response(
                200,
                json=rotated_disco,
                headers={"Cache-Control": uncacheable_header},
            )

        respx.get(DISCO_URL).mock(side_effect=handler)

        primed = _get_disco_response(DISCO_URL)
        assert primed.is_successful is True
        cache_key = (DISCO_URL, True)
        assert cache_key in sync_tv._disco_cache

        # Manually expire the entry without removing it — this is the state
        # the cache lands in when the entry's TTL elapses naturally. Backdate
        # cached_at past the TTL boundary on the monotonic clock (post-#400
        # the cache compares ages via time.monotonic, not time.time, so a
        # literal 0.0 is just process-startup time and may still be fresh in
        # short-running tests).
        stale_entry = sync_tv._disco_cache[cache_key]
        sync_tv._disco_cache[cache_key] = type(stale_entry)(
            response=stale_entry.response,
            cached_at=time.monotonic() - stale_entry.ttl - 1,
            ttl=stale_entry.ttl,
        )

        _get_disco_response(DISCO_URL)
        # The expired entry must be popped, not left as dead weight.
        assert cache_key not in sync_tv._disco_cache


class TestAsyncRefreshInvalidatesStaleOnUncacheable:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("uncacheable_header", REFRESH_UNCACHEABLE_TEST_CASES)
    @respx.mock
    async def test_refresh_pops_stale_entry_when_response_uncacheable_async(
        self, uncacheable_header: str
    ):
        old_key = _key_with_kid("old-kid")
        new_key = _key_with_kid("new-kid")
        call_log: list[int] = []

        def handler(_request: httpx.Request) -> httpx.Response:
            call_log.append(1)
            if len(call_log) == 1:
                return httpx.Response(
                    200,
                    json={"keys": [old_key]},
                    headers={"Cache-Control": "max-age=3600"},
                )
            return httpx.Response(
                200,
                json={"keys": [new_key]},
                headers={"Cache-Control": uncacheable_header},
            )

        respx.get(JWKS_URL).mock(side_effect=handler)

        primed = await async_get_cached_jwks(JWKS_URL)
        assert primed.is_successful is True
        assert JWKS_URL in aio_tv._jwks_cache
        assert _kids(aio_tv._jwks_cache[JWKS_URL].response) == {"old-kid"}

        refreshed = await aio_tv._refresh_jwks(JWKS_URL)
        assert refreshed.is_successful is True
        assert _kids(refreshed) == {"new-kid"}
        assert JWKS_URL not in aio_tv._jwks_cache


# ============================================================================
# Empty-keys responses must never replace a populated cache entry, and must
# not be stored from a fresh fetch either. An empty ``keys: []`` from the
# provider is treated as a transient upstream blip — never a valid replacement.
# Without this guard, a transient empty-200 response from the OP poisons the
# cache for up to 24h, breaking every token validation in the deployment.
# ============================================================================


class TestSyncEmptyKeysNotCached:
    @respx.mock
    def test_refresh_with_empty_keys_retains_existing_entry(self):
        old_key = _key_with_kid("retained-kid")
        call_log: list[int] = []

        def handler(_request: httpx.Request) -> httpx.Response:
            call_log.append(1)
            if len(call_log) == 1:
                return httpx.Response(
                    200,
                    json={"keys": [old_key]},
                    headers={"Cache-Control": "max-age=3600"},
                )
            return httpx.Response(
                200,
                json={"keys": []},
                headers={"Cache-Control": "max-age=3600"},
            )

        respx.get(JWKS_URL).mock(side_effect=handler)

        primed = _get_cached_jwks(JWKS_URL)
        assert primed.is_successful is True

        refreshed = sync_tv._refresh_jwks(JWKS_URL)
        # The empty response is returned to the caller (no lying about what
        # the upstream sent), but the cache retains the last-known-good keys.
        assert refreshed.is_successful is True
        assert refreshed.keys == []
        assert JWKS_URL in sync_tv._jwks_cache
        assert _kids(sync_tv._jwks_cache[JWKS_URL].response) == {"retained-kid"}

    @respx.mock
    def test_initial_fetch_with_empty_keys_not_cached(self):
        respx.get(JWKS_URL).mock(
            return_value=httpx.Response(
                200,
                json={"keys": []},
                headers={"Cache-Control": "max-age=3600"},
            )
        )

        response = _get_cached_jwks(JWKS_URL)
        assert response.is_successful is True
        assert response.keys == []
        # Empty-keys responses are never stored, so a subsequent call must
        # re-fetch rather than serve a poisoned entry.
        assert JWKS_URL not in sync_tv._jwks_cache


class TestAsyncEmptyKeysNotCached:
    @pytest.mark.asyncio
    @respx.mock
    async def test_refresh_with_empty_keys_retains_existing_entry_async(self):
        old_key = _key_with_kid("retained-kid")
        call_log: list[int] = []

        def handler(_request: httpx.Request) -> httpx.Response:
            call_log.append(1)
            if len(call_log) == 1:
                return httpx.Response(
                    200,
                    json={"keys": [old_key]},
                    headers={"Cache-Control": "max-age=3600"},
                )
            return httpx.Response(
                200,
                json={"keys": []},
                headers={"Cache-Control": "max-age=3600"},
            )

        respx.get(JWKS_URL).mock(side_effect=handler)

        await async_get_cached_jwks(JWKS_URL)
        refreshed = await aio_tv._refresh_jwks(JWKS_URL)
        assert refreshed.is_successful is True
        assert refreshed.keys == []
        assert JWKS_URL in aio_tv._jwks_cache
        assert _kids(aio_tv._jwks_cache[JWKS_URL].response) == {"retained-kid"}


# ============================================================================
# Empty-keys + uncacheable header joint case. The dataclass-level invariant
# is "empty keys never replaces working keys" — checking the empty-keys
# branch *before* the uncacheable branch ensures a malformed
# ``200 {"keys": []}`` paired with ``Cache-Control: no-cache`` does not pop
# the working entry on a transient empty-body blip combined with a header
# bug. Without this ordering, the cache is silently emptied by a single
# bad-response coincidence.
# ============================================================================


class TestEmptyKeysWithUncacheableHeaderRetains:
    @respx.mock
    @pytest.mark.parametrize(
        "uncacheable_header", ["no-store", "no-cache", "no-store, max-age=300"]
    )
    def test_sync_empty_keys_with_uncacheable_header_retains(
        self, uncacheable_header: str
    ):
        old_key = _key_with_kid("retained-kid")
        call_log: list[int] = []

        def handler(_request: httpx.Request) -> httpx.Response:
            call_log.append(1)
            if len(call_log) == 1:
                return httpx.Response(
                    200,
                    json={"keys": [old_key]},
                    headers={"Cache-Control": "max-age=3600"},
                )
            return httpx.Response(
                200,
                json={"keys": []},
                headers={"Cache-Control": uncacheable_header},
            )

        respx.get(JWKS_URL).mock(side_effect=handler)

        _get_cached_jwks(JWKS_URL)
        sync_tv._refresh_jwks(JWKS_URL)
        assert JWKS_URL in sync_tv._jwks_cache
        assert _kids(sync_tv._jwks_cache[JWKS_URL].response) == {"retained-kid"}

    @pytest.mark.asyncio
    @respx.mock
    @pytest.mark.parametrize(
        "uncacheable_header", ["no-store", "no-cache", "no-store, max-age=300"]
    )
    async def test_async_empty_keys_with_uncacheable_header_retains(
        self, uncacheable_header: str
    ):
        old_key = _key_with_kid("retained-kid")
        call_log: list[int] = []

        def handler(_request: httpx.Request) -> httpx.Response:
            call_log.append(1)
            if len(call_log) == 1:
                return httpx.Response(
                    200,
                    json={"keys": [old_key]},
                    headers={"Cache-Control": "max-age=3600"},
                )
            return httpx.Response(
                200,
                json={"keys": []},
                headers={"Cache-Control": uncacheable_header},
            )

        respx.get(JWKS_URL).mock(side_effect=handler)

        await async_get_cached_jwks(JWKS_URL)
        await aio_tv._refresh_jwks(JWKS_URL)
        assert JWKS_URL in aio_tv._jwks_cache
        assert _kids(aio_tv._jwks_cache[JWKS_URL].response) == {"retained-kid"}


# ============================================================================
# Network errors must never replace a populated cache entry (retain-on-error,
# mirroring jose4j's setRetainCacheOnErrorDuration semantics). Combined with
# the existing "failed responses not cached" tests above, this proves the
# full failure-mode matrix: success+cacheable=write, success+uncacheable=pop,
# success+empty=retain, failed=retain.
# ============================================================================


class TestRetainOnError:
    @respx.mock
    def test_sync_refresh_failure_retains_existing_entry(self):
        old_key = _key_with_kid("retained-kid")
        call_log: list[int] = []

        def handler(_request: httpx.Request) -> httpx.Response:
            call_log.append(1)
            if len(call_log) == 1:
                return httpx.Response(
                    200,
                    json={"keys": [old_key]},
                    headers={"Cache-Control": "max-age=3600"},
                )
            return httpx.Response(404, text="not found")

        respx.get(JWKS_URL).mock(side_effect=handler)

        _get_cached_jwks(JWKS_URL)
        refreshed = sync_tv._refresh_jwks(JWKS_URL)
        assert refreshed.is_successful is False
        assert JWKS_URL in sync_tv._jwks_cache
        assert _kids(sync_tv._jwks_cache[JWKS_URL].response) == {"retained-kid"}

    @pytest.mark.asyncio
    @respx.mock
    async def test_async_refresh_failure_retains_existing_entry(self):
        old_key = _key_with_kid("retained-kid")
        call_log: list[int] = []

        def handler(_request: httpx.Request) -> httpx.Response:
            call_log.append(1)
            if len(call_log) == 1:
                return httpx.Response(
                    200,
                    json={"keys": [old_key]},
                    headers={"Cache-Control": "max-age=3600"},
                )
            return httpx.Response(404, text="not found")

        respx.get(JWKS_URL).mock(side_effect=handler)

        await async_get_cached_jwks(JWKS_URL)
        refreshed = await aio_tv._refresh_jwks(JWKS_URL)
        assert refreshed.is_successful is False
        assert JWKS_URL in aio_tv._jwks_cache
        assert _kids(aio_tv._jwks_cache[JWKS_URL].response) == {"retained-kid"}
