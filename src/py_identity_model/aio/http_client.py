"""
Asynchronous HTTP client with connection pooling and retry logic.

This module provides a singleton async HTTP client with connection pooling and
automatic retry logic for transient failures like rate limiting.

Environment Variables:
    HTTP_RETRY_MAX_ATTEMPTS: Maximum number of retry attempts (default: 3)
    HTTP_RETRY_BASE_DELAY: Base delay in seconds for exponential backoff (default: 1.0)
    HTTP_TIMEOUT: Request timeout in seconds (default: 30.0)
"""

import asyncio
from functools import wraps
import threading

import httpx

from ..core.http_utils import (
    calculate_delay,
    get_retry_config,
    get_timeout,
    should_retry_response,
)
from ..logging_config import logger
from ..ssl_config import get_ssl_verify


# Thread lock for async client creation (protects multi-threaded initialization)
_async_client_creation_lock = threading.Lock()

# Async lock for async client cleanup (protects async operations)
_async_client_cleanup_lock: asyncio.Lock | None = None

# Cached async client instance
_async_http_client: httpx.AsyncClient | None = None


def _log_retry(message: str, delay: float, attempt: int, retries: int) -> None:
    """Log a retry attempt warning."""
    logger.warning(
        f"{message}, retrying in {delay}s (attempt {attempt + 1}/{retries})"
    )


def _get_retry_params(
    max_retries: int | None, base_delay: float | None
) -> tuple[int, float]:
    """
    Get retry parameters from arguments or environment.

    Args:
        max_retries: Explicit max retries or None
        base_delay: Explicit base delay or None

    Returns:
        tuple[int, float]: (retries, delay_base)
    """
    env_max_retries, env_base_delay = get_retry_config()
    retries = max_retries if max_retries is not None else env_max_retries
    delay_base = base_delay if base_delay is not None else env_base_delay
    return retries, delay_base


def retry_with_backoff_async(
    max_retries: int | None = None, base_delay: float | None = None
):
    """
    Decorator to retry async HTTP requests on rate limiting with exponential backoff.

    Args:
        max_retries: Maximum number of retry attempts (default: from HTTP_RETRY_MAX_ATTEMPTS env or 3)
        base_delay: Base delay in seconds for exponential backoff (default: from HTTP_RETRY_BASE_DELAY env or 1.0)

    Returns:
        Decorated async function that retries on 429 and 5xx errors

    Environment Variables:
        HTTP_RETRY_MAX_ATTEMPTS: Default max retries if not specified
        HTTP_RETRY_BASE_DELAY: Default base delay if not specified
    """

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            retries, delay_base = _get_retry_params(max_retries, base_delay)
            last_exception: httpx.RequestError | None = None

            for attempt in range(retries + 1):
                try:
                    response = await func(*args, **kwargs)

                    # Check if response needs retry (429 or 5xx with retries remaining)
                    if should_retry_response(response, attempt, retries):
                        delay = calculate_delay(delay_base, attempt)
                        _log_retry(
                            f"HTTP {response.status_code}",
                            delay,
                            attempt,
                            retries,
                        )
                        await asyncio.sleep(delay)
                        continue

                    return response

                except httpx.RequestError as e:
                    last_exception = e
                    if attempt < retries:
                        delay = calculate_delay(delay_base, attempt)
                        _log_retry(
                            f"Request error: {e}", delay, attempt, retries
                        )
                        await asyncio.sleep(delay)
                        continue
                    raise

            # Exhausted all retries - return last response or raise last exception
            if last_exception:
                raise last_exception
            raise RuntimeError("No response received after retries")

        return wrapper

    return decorator


def get_async_http_client() -> httpx.AsyncClient:
    """
    Get a persistent async HTTP client with connection pooling.

    Returns a singleton httpx.AsyncClient that reuses connections, improving
    performance for multiple HTTP requests. Use @retry_with_backoff_async
    decorator on HTTP calls for automatic retry logic.

    Returns:
        httpx.AsyncClient: Configured async HTTP client with connection pooling

    Environment Variables:
        HTTP_TIMEOUT: Request timeout in seconds (default: 30.0)

    Note:
        The client uses default limits:
        - max_connections: 100
        - max_keepalive_connections: 20
        - keepalive_expiry: 5.0 seconds

        Thread-safe: Uses a lock to prevent race conditions when creating
        the async client from multiple threads simultaneously.
    """
    global _async_http_client

    # Fast path: client already exists
    if _async_http_client is not None:
        return _async_http_client

    # Slow path: need to create client with lock
    with _async_client_creation_lock:
        # Double-check: another thread might have created it while we waited
        if _async_http_client is not None:
            return _async_http_client

        # Create client - httpx.AsyncClient creation is synchronous and safe
        timeout = get_timeout()
        _async_http_client = httpx.AsyncClient(
            verify=get_ssl_verify(),
            timeout=timeout,
            follow_redirects=True,
        )
        return _async_http_client


async def close_async_http_client() -> None:
    """
    Close the persistent async HTTP client and clear the cache.

    This should be called when shutting down the application to properly
    clean up resources. Not calling this will leave connections open, but
    they will be cleaned up when the process exits.

    Note:
        This function uses asyncio.Lock for proper async cleanup without
        blocking the event loop.
    """
    global _async_http_client, _async_client_cleanup_lock

    # Initialize the async cleanup lock if needed (lazy initialization)
    if _async_client_cleanup_lock is None:
        _async_client_cleanup_lock = asyncio.Lock()

    if _async_http_client is not None:
        async with _async_client_cleanup_lock:
            if _async_http_client is not None:
                await _async_http_client.aclose()
                _async_http_client = None


def _reset_async_http_client() -> None:
    """
    Reset the async HTTP client cache (for testing purposes only).

    This function is intended for use in tests to clear the cached async
    HTTP client instance. It should not be called in production code.
    """
    global _async_http_client, _async_client_cleanup_lock
    with _async_client_creation_lock:
        if _async_http_client is not None:
            # Note: Synchronous close for testing - may leave connections open
            # In production, use close_async_http_client() for proper cleanup
            _async_http_client = None
        _async_client_cleanup_lock = None


__all__ = [
    "close_async_http_client",
    "get_async_http_client",
    "retry_with_backoff_async",
]
