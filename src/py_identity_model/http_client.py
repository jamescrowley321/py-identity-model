"""
HTTP client configuration with connection pooling and retry logic.

This module provides shared HTTP clients with connection pooling and automatic
retry logic for transient failures like rate limiting.

Environment Variables:
    HTTP_RETRY_MAX_ATTEMPTS: Maximum number of retry attempts (default: 3)
    HTTP_RETRY_BASE_DELAY: Base delay in seconds for exponential backoff (default: 1.0)
    HTTP_TIMEOUT: Request timeout in seconds (default: 30.0)
"""

import asyncio
from functools import lru_cache, wraps
import os
import threading
import time

import httpx

from .logging_config import logger
from .ssl_config import get_ssl_verify


# Thread lock for async client creation
_async_client_lock = threading.Lock()


def _get_retry_config() -> tuple[int, float]:
    """
    Get retry configuration from environment variables.

    Returns:
        tuple: (max_retries, base_delay)
    """
    max_retries = int(os.getenv("HTTP_RETRY_MAX_ATTEMPTS", "3"))
    base_delay = float(os.getenv("HTTP_RETRY_BASE_DELAY", "1.0"))
    return max_retries, base_delay


def _get_timeout() -> float:
    """
    Get HTTP timeout from environment variable.

    Returns:
        float: Timeout in seconds
    """
    return float(os.getenv("HTTP_TIMEOUT", "30.0"))


def _should_retry_response(
    response: httpx.Response, attempt: int, retries: int
) -> bool:
    """Check if response should be retried."""
    return (
        response.status_code == 429 or response.status_code >= 500
    ) and attempt < retries


def _calculate_delay(base_delay: float, attempt: int) -> float:
    """Calculate exponential backoff delay."""
    return base_delay * (2**attempt)


def _log_and_sleep(
    delay: float, message: str, attempt: int, retries: int
) -> None:
    """Log retry attempt and sleep."""
    logger.warning(
        f"{message}, retrying in {delay}s (attempt {attempt + 1}/{retries})"
    )
    time.sleep(delay)


def retry_on_rate_limit(
    max_retries: int | None = None, base_delay: float | None = None
):
    """
    Decorator to retry HTTP requests on rate limiting with exponential backoff.

    Args:
        max_retries: Maximum number of retry attempts (default: from HTTP_RETRY_MAX_ATTEMPTS env or 3)
        base_delay: Base delay in seconds for exponential backoff (default: from HTTP_RETRY_BASE_DELAY env or 1.0)

    Returns:
        Decorated function that retries on 429 and 5xx errors

    Environment Variables:
        HTTP_RETRY_MAX_ATTEMPTS: Default max retries if not specified
        HTTP_RETRY_BASE_DELAY: Default base delay if not specified
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Get retry config from env if not provided
            env_max_retries, env_base_delay = _get_retry_config()
            retries = (
                max_retries if max_retries is not None else env_max_retries
            )
            delay_base = (
                base_delay if base_delay is not None else env_base_delay
            )

            last_exception = None
            response = None

            for attempt in range(retries + 1):
                try:
                    response = func(*args, **kwargs)

                    # Retry on rate limiting (429) or server errors (5xx)
                    if _should_retry_response(response, attempt, retries):
                        delay = _calculate_delay(delay_base, attempt)
                        _log_and_sleep(
                            delay,
                            f"HTTP {response.status_code} received",
                            attempt,
                            retries,
                        )
                        continue

                    # Success or non-retryable error
                    return response

                except httpx.RequestError as e:
                    last_exception = e
                    if attempt < retries:
                        delay = _calculate_delay(delay_base, attempt)
                        _log_and_sleep(
                            delay, f"Request error: {e}", attempt, retries
                        )
                        continue
                    raise

            # If we exhausted all retries without success, return last response or raise
            if last_exception:
                raise last_exception
            if response is not None:
                return response
            # This should never happen, but satisfy type checker
            raise RuntimeError("No response received after retries")

        return wrapper

    return decorator


@lru_cache(maxsize=1)
def get_http_client() -> httpx.Client:
    """
    Get a persistent HTTP client with connection pooling.

    Returns a singleton httpx.Client that reuses connections, improving
    performance for multiple HTTP requests. Use @retry_on_rate_limit
    decorator on HTTP calls for automatic retry logic.

    Returns:
        httpx.Client: Configured HTTP client with connection pooling

    Environment Variables:
        HTTP_TIMEOUT: Request timeout in seconds (default: 30.0)

    Note:
        The client uses default limits:
        - max_connections: 100
        - max_keepalive_connections: 20
        - keepalive_expiry: 5.0 seconds
    """
    timeout = _get_timeout()
    return httpx.Client(
        verify=get_ssl_verify(),
        timeout=timeout,
        follow_redirects=True,
    )


def close_http_client() -> None:
    """
    Close the persistent HTTP client and clear the cache.

    This should be called when shutting down the application to properly
    clean up resources. Not calling this will leave connections open, but
    they will be cleaned up when the process exits.
    """
    client = get_http_client.cache_info()
    if client.currsize > 0:
        get_http_client().close()
        get_http_client.cache_clear()


async def _log_and_sleep_async(
    delay: float, message: str, attempt: int, retries: int
) -> None:
    """Log retry attempt and sleep asynchronously."""
    logger.warning(
        f"{message}, retrying in {delay}s (attempt {attempt + 1}/{retries})"
    )
    await asyncio.sleep(delay)


def retry_on_rate_limit_async(
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
            # Get retry config from env if not provided
            env_max_retries, env_base_delay = _get_retry_config()
            retries = (
                max_retries if max_retries is not None else env_max_retries
            )
            delay_base = (
                base_delay if base_delay is not None else env_base_delay
            )

            last_exception = None
            response = None

            for attempt in range(retries + 1):
                try:
                    response = await func(*args, **kwargs)

                    # Retry on rate limiting (429) or server errors (5xx)
                    if _should_retry_response(response, attempt, retries):
                        delay = _calculate_delay(delay_base, attempt)
                        await _log_and_sleep_async(
                            delay,
                            f"HTTP {response.status_code} received",
                            attempt,
                            retries,
                        )
                        continue

                    # Success or non-retryable error
                    return response

                except httpx.RequestError as e:
                    last_exception = e
                    if attempt < retries:
                        delay = _calculate_delay(delay_base, attempt)
                        await _log_and_sleep_async(
                            delay, f"Request error: {e}", attempt, retries
                        )
                        continue
                    raise

            # If we exhausted all retries without success, return last response or raise
            if last_exception:
                raise last_exception
            if response is not None:
                return response
            # This should never happen, but satisfy type checker
            raise RuntimeError("No response received after retries")

        return wrapper

    return decorator


# Cached async client instance
_async_http_client: httpx.AsyncClient | None = None


def get_async_http_client() -> httpx.AsyncClient:
    """
    Get a persistent async HTTP client with connection pooling.

    Returns a singleton httpx.AsyncClient that reuses connections, improving
    performance for multiple HTTP requests. Use @retry_on_rate_limit_async
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

    if _async_http_client is None:
        with _async_client_lock:
            # Double-check pattern to avoid race conditions
            if _async_http_client is None:
                timeout = _get_timeout()
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
    """
    global _async_http_client

    if _async_http_client is not None:
        with _async_client_lock:
            if _async_http_client is not None:
                await _async_http_client.aclose()
                _async_http_client = None


def _reset_async_http_client() -> None:
    """
    Reset the async HTTP client cache (for testing purposes only).

    This function is intended for use in tests to clear the cached async
    HTTP client instance. It should not be called in production code.
    """
    global _async_http_client
    with _async_client_lock:
        _async_http_client = None


__all__ = [
    "close_async_http_client",
    "close_http_client",
    "get_async_http_client",
    "get_http_client",
    "retry_on_rate_limit",
    "retry_on_rate_limit_async",
]
