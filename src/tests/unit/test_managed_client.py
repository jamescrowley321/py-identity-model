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
