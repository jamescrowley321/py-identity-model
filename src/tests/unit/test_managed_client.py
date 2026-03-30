"""Unit tests for managed HTTP client classes (sync and async)."""

import httpx
import pytest

from py_identity_model.aio.managed_client import AsyncHTTPClient
from py_identity_model.sync.managed_client import HTTPClient


@pytest.mark.unit
class TestHTTPClient:
    """Tests for the sync HTTPClient wrapper."""

    def test_creates_owned_client_by_default(self):
        client = HTTPClient()
        assert isinstance(client.client, httpx.Client)
        client.close()

    def test_wraps_existing_client(self):
        raw = httpx.Client()
        client = HTTPClient(client=raw)
        assert client.client is raw
        client.close()  # Should NOT close raw (not owned)
        assert not raw.is_closed
        raw.close()

    def test_close_owned_client(self):
        client = HTTPClient()
        underlying = client.client
        client.close()
        assert underlying.is_closed

    def test_close_unowned_is_noop(self):
        raw = httpx.Client()
        client = HTTPClient(client=raw)
        client.close()
        assert not raw.is_closed
        raw.close()

    def test_context_manager(self):
        with HTTPClient() as client:
            assert isinstance(client.client, httpx.Client)
            underlying = client.client
        assert underlying.is_closed

    def test_context_manager_unowned(self):
        raw = httpx.Client()
        with HTTPClient(client=raw) as client:
            assert client.client is raw
        assert not raw.is_closed
        raw.close()

    def test_custom_timeout(self):
        client = HTTPClient(timeout=60.0)
        assert client.client.timeout.connect == 60.0
        client.close()

    def test_custom_verify_false(self):
        client = HTTPClient(verify=False)
        assert isinstance(client.client, httpx.Client)
        client.close()

    def test_access_after_close_raises(self):
        client = HTTPClient()
        client.close()
        with pytest.raises(RuntimeError, match="has been closed"):
            _ = client.client

    def test_double_close_is_idempotent(self):
        client = HTTPClient()
        client.close()
        client.close()  # Should not raise

    def test_reject_timeout_with_existing_client(self):
        raw = httpx.Client()
        with pytest.raises(ValueError, match="cannot be specified"):
            HTTPClient(client=raw, timeout=5.0)
        raw.close()

    def test_reject_verify_with_existing_client(self):
        raw = httpx.Client()
        with pytest.raises(ValueError, match="cannot be specified"):
            HTTPClient(client=raw, verify=False)
        raw.close()

    def test_unowned_close_blocks_further_access(self):
        raw = httpx.Client()
        client = HTTPClient(client=raw)
        client.close()
        with pytest.raises(RuntimeError, match="has been closed"):
            _ = client.client
        assert not raw.is_closed
        raw.close()


@pytest.mark.unit
class TestAsyncHTTPClient:
    """Tests for the async AsyncHTTPClient wrapper."""

    def test_creates_owned_client_by_default(self):
        client = AsyncHTTPClient()
        assert isinstance(client.client, httpx.AsyncClient)

    def test_wraps_existing_client(self):
        raw = httpx.AsyncClient()
        client = AsyncHTTPClient(client=raw)
        assert client.client is raw

    @pytest.mark.asyncio
    async def test_close_owned_client(self):
        client = AsyncHTTPClient()
        underlying = client.client
        await client.close()
        assert underlying.is_closed

    @pytest.mark.asyncio
    async def test_close_unowned_is_noop(self):
        raw = httpx.AsyncClient()
        client = AsyncHTTPClient(client=raw)
        await client.close()
        assert not raw.is_closed
        await raw.aclose()

    @pytest.mark.asyncio
    async def test_async_context_manager(self):
        async with AsyncHTTPClient() as client:
            assert isinstance(client.client, httpx.AsyncClient)
            underlying = client.client
        assert underlying.is_closed

    @pytest.mark.asyncio
    async def test_async_context_manager_unowned(self):
        raw = httpx.AsyncClient()
        async with AsyncHTTPClient(client=raw) as client:
            assert client.client is raw
        assert not raw.is_closed
        await raw.aclose()

    def test_custom_timeout(self):
        client = AsyncHTTPClient(timeout=60.0)
        assert client.client.timeout.connect == 60.0

    def test_custom_verify_false(self):
        client = AsyncHTTPClient(verify=False)
        assert isinstance(client.client, httpx.AsyncClient)

    @pytest.mark.asyncio
    async def test_access_after_close_raises(self):
        client = AsyncHTTPClient()
        await client.close()
        with pytest.raises(RuntimeError, match="has been closed"):
            _ = client.client

    @pytest.mark.asyncio
    async def test_double_close_is_idempotent(self):
        client = AsyncHTTPClient()
        await client.close()
        await client.close()  # Should not raise

    def test_reject_timeout_with_existing_client(self):
        raw = httpx.AsyncClient()
        with pytest.raises(ValueError, match="cannot be specified"):
            AsyncHTTPClient(client=raw, timeout=5.0)

    def test_reject_verify_with_existing_client(self):
        raw = httpx.AsyncClient()
        with pytest.raises(ValueError, match="cannot be specified"):
            AsyncHTTPClient(client=raw, verify=False)

    @pytest.mark.asyncio
    async def test_unowned_close_blocks_further_access(self):
        raw = httpx.AsyncClient()
        client = AsyncHTTPClient(client=raw)
        await client.close()
        with pytest.raises(RuntimeError, match="has been closed"):
            _ = client.client
        assert not raw.is_closed
        await raw.aclose()
