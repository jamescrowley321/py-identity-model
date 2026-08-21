"""Tests for HTTP client retry logic and edge cases."""

from unittest.mock import MagicMock

import httpx
import pytest

from py_identity_model.aio.http_client import (
    _reset_async_http_client,
    close_async_http_client,
    get_async_http_client,
    retry_with_backoff_async,
)
from py_identity_model.ssl_config import get_ssl_verify
from py_identity_model.sync.http_client import (
    _reset_http_client,
    close_http_client,
    get_http_client,
    retry_with_backoff,
)


# Test constants
HTTP_OK = 200
EXPECTED_CALLS_AFTER_TWO_RETRIES = 3
EXPECTED_CALLS_AFTER_ONE_RETRY = 2
CALLS_BEFORE_SUCCESS_ON_THIRD = 3
CALLS_BEFORE_SUCCESS_ON_SECOND = 2


class TestSyncRetryWithBackoff:
    """Tests for synchronous retry_with_backoff decorator."""

    def test_retry_exhaustion_raises_last_exception(self, monkeypatch):
        """Test that after exhausting retries, the last exception is raised."""
        monkeypatch.setenv("HTTP_RETRY_MAX_ATTEMPTS", "2")
        monkeypatch.setenv("HTTP_RETRY_BASE_DELAY", "0.01")

        call_count = 0

        @retry_with_backoff()
        def failing_request():
            nonlocal call_count
            call_count += 1
            raise httpx.RequestError("Connection failed")

        with pytest.raises(httpx.RequestError, match="Connection failed"):
            failing_request()

        # Should have attempted max_retries + 1 times (initial + retries)
        assert call_count == EXPECTED_CALLS_AFTER_TWO_RETRIES

    def test_retry_on_429_then_success(self, monkeypatch):
        """Test that retry works when server returns 429 then succeeds."""
        monkeypatch.setenv("HTTP_RETRY_MAX_ATTEMPTS", "3")
        monkeypatch.setenv("HTTP_RETRY_BASE_DELAY", "0.01")

        call_count = 0

        @retry_with_backoff()
        def rate_limited_then_success():
            nonlocal call_count
            call_count += 1
            if call_count < CALLS_BEFORE_SUCCESS_ON_THIRD:
                response = MagicMock()
                response.status_code = 429
                return response
            response = MagicMock()
            response.status_code = HTTP_OK
            return response

        result = rate_limited_then_success()
        assert result.status_code == HTTP_OK
        assert call_count == EXPECTED_CALLS_AFTER_TWO_RETRIES

    def test_retry_on_5xx_errors(self, monkeypatch):
        """Test that retry works on 5xx server errors."""
        monkeypatch.setenv("HTTP_RETRY_MAX_ATTEMPTS", "2")
        monkeypatch.setenv("HTTP_RETRY_BASE_DELAY", "0.01")

        call_count = 0

        @retry_with_backoff()
        def server_error_then_success():
            nonlocal call_count
            call_count += 1
            if call_count < CALLS_BEFORE_SUCCESS_ON_SECOND:
                response = MagicMock()
                response.status_code = 503
                return response
            response = MagicMock()
            response.status_code = HTTP_OK
            return response

        result = server_error_then_success()
        assert result.status_code == HTTP_OK
        assert call_count == EXPECTED_CALLS_AFTER_ONE_RETRY


class TestAsyncRetryWithBackoff:
    """Tests for asynchronous retry_with_backoff_async decorator."""

    @pytest.mark.asyncio
    async def test_retry_exhaustion_raises_last_exception(self, monkeypatch):
        """Test that after exhausting retries, the last exception is raised."""
        monkeypatch.setenv("HTTP_RETRY_MAX_ATTEMPTS", "2")
        monkeypatch.setenv("HTTP_RETRY_BASE_DELAY", "0.01")

        call_count = 0

        @retry_with_backoff_async()
        async def failing_request():
            nonlocal call_count
            call_count += 1
            raise httpx.RequestError("Connection failed")

        with pytest.raises(httpx.RequestError, match="Connection failed"):
            await failing_request()

        # Should have attempted max_retries + 1 times (initial + retries)
        assert call_count == EXPECTED_CALLS_AFTER_TWO_RETRIES

    @pytest.mark.asyncio
    async def test_retry_on_429_then_success(self, monkeypatch):
        """Test that retry works when server returns 429 then succeeds."""
        monkeypatch.setenv("HTTP_RETRY_MAX_ATTEMPTS", "3")
        monkeypatch.setenv("HTTP_RETRY_BASE_DELAY", "0.01")

        call_count = 0

        @retry_with_backoff_async()
        async def rate_limited_then_success():
            nonlocal call_count
            call_count += 1
            if call_count < CALLS_BEFORE_SUCCESS_ON_THIRD:
                response = MagicMock()
                response.status_code = 429
                return response
            response = MagicMock()
            response.status_code = HTTP_OK
            return response

        result = await rate_limited_then_success()
        assert result.status_code == HTTP_OK
        assert call_count == EXPECTED_CALLS_AFTER_TWO_RETRIES

    @pytest.mark.asyncio
    async def test_retry_on_5xx_errors(self, monkeypatch):
        """Test that retry works on 5xx server errors."""
        monkeypatch.setenv("HTTP_RETRY_MAX_ATTEMPTS", "2")
        monkeypatch.setenv("HTTP_RETRY_BASE_DELAY", "0.01")

        call_count = 0

        @retry_with_backoff_async()
        async def server_error_then_success():
            nonlocal call_count
            call_count += 1
            if call_count < CALLS_BEFORE_SUCCESS_ON_SECOND:
                response = MagicMock()
                response.status_code = 503
                return response
            response = MagicMock()
            response.status_code = HTTP_OK
            return response

        result = await server_error_then_success()
        assert result.status_code == HTTP_OK
        assert call_count == EXPECTED_CALLS_AFTER_ONE_RETRY


class TestSyncHTTPClientLifecycle:
    """Tests for sync HTTP client lifecycle management."""

    def test_close_http_client_when_none(self):
        """Test closing HTTP client when it was never created."""
        get_ssl_verify.cache_clear()
        _reset_http_client()

        # Should not raise even when no client exists
        close_http_client()

    def test_get_http_client_returns_same_instance(self):
        """Test that get_http_client returns the same instance for same thread."""
        get_ssl_verify.cache_clear()
        _reset_http_client()

        client1 = get_http_client()
        client2 = get_http_client()

        assert client1 is client2

        # Cleanup
        close_http_client()


class TestAsyncHTTPClientLifecycle:
    """Tests for async HTTP client lifecycle management."""

    @pytest.mark.asyncio
    async def test_close_async_http_client_when_none(self):
        """Test closing async HTTP client when it was never created."""
        get_ssl_verify.cache_clear()
        _reset_async_http_client()

        # Should not raise even when no client exists
        await close_async_http_client()

    @pytest.mark.asyncio
    async def test_close_async_http_client_twice(self):
        """Test closing async HTTP client twice is safe."""
        get_ssl_verify.cache_clear()
        _reset_async_http_client()

        # Create a client
        client = get_async_http_client()
        assert client is not None

        # Close it twice - should not raise
        await close_async_http_client()
        await close_async_http_client()

    @pytest.mark.asyncio
    async def test_get_async_http_client_returns_same_instance(self):
        """Test that get_async_http_client returns the same instance."""
        get_ssl_verify.cache_clear()
        _reset_async_http_client()

        client1 = get_async_http_client()
        client2 = get_async_http_client()

        assert client1 is client2

        # Cleanup
        await close_async_http_client()
