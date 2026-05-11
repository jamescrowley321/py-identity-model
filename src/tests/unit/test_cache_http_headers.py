"""
Tests for HTTP cache header semantics in JWKS and discovery caches.

Covers three correctness fixes:
1. Failed JWKS/discovery responses must not be cached (a transient 5xx or
   network error would otherwise poison the cache for up to 24h).
2. ``Cache-Control: no-store`` must not be cached at all (RFC 7234 §5.2.2.5).
3. ``Cache-Control: no-cache`` must always re-fetch (RFC 7234 §5.2.2.4) —
   simplest correct behavior is to skip caching.
"""

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
