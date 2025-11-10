"""
Synchronous HTTP client with connection pooling and retry logic.

This module provides thread-local HTTP clients with connection pooling and
automatic retry logic for transient failures like rate limiting.

Environment Variables:
    HTTP_RETRY_MAX_ATTEMPTS: Maximum number of retry attempts (default: 3)
    HTTP_RETRY_BASE_DELAY: Base delay in seconds for exponential backoff (default: 1.0)
    HTTP_TIMEOUT: Request timeout in seconds (default: 30.0)
"""

from functools import wraps
import threading
import time

import httpx

from ..core.http_utils import (
    calculate_delay,
    get_retry_config,
    get_timeout,
    should_retry_response,
)
from ..logging_config import logger
from ..ssl_config import get_ssl_verify


# Thread-local storage for sync HTTP client
_thread_local = threading.local()


def _log_and_sleep(
    delay: float, message: str, attempt: int, retries: int
) -> None:
    """Log retry attempt and sleep."""
    logger.warning(
        f"{message}, retrying in {delay}s (attempt {attempt + 1}/{retries})"
    )
    time.sleep(delay)


def _handle_retry_response(
    response: httpx.Response,
    attempt: int,
    retries: int,
    delay_base: float,
) -> bool:
    """
    Handle response that may need retry.

    Args:
        response: HTTP response to check
        attempt: Current attempt number
        retries: Maximum number of retries
        delay_base: Base delay for exponential backoff

    Returns:
        bool: True if should continue retry loop, False if should return response
    """
    if should_retry_response(response, attempt, retries):
        delay = calculate_delay(delay_base, attempt)
        _log_and_sleep(
            delay,
            f"HTTP {response.status_code} received",
            attempt,
            retries,
        )
        return True
    return False


def _handle_retry_exception(
    exception: httpx.RequestError,
    attempt: int,
    retries: int,
    delay_base: float,
) -> None:
    """
    Handle exception that may need retry.

    Args:
        exception: Request error that occurred
        attempt: Current attempt number
        retries: Maximum number of retries
        delay_base: Base delay for exponential backoff

    Raises:
        httpx.RequestError: If no more retries available
    """
    if attempt < retries:
        delay = calculate_delay(delay_base, attempt)
        _log_and_sleep(delay, f"Request error: {exception}", attempt, retries)
    else:
        raise exception


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


def retry_with_backoff(
    max_retries: int | None = None, base_delay: float | None = None
):
    """
    Decorator to retry HTTP requests with exponential backoff.

    Retries on transient errors including rate limiting (429) and server errors (5xx).

    Args:
        max_retries: Maximum number of retry attempts (default: from HTTP_RETRY_MAX_ATTEMPTS env or 3)
        base_delay: Base delay in seconds for exponential backoff (default: from HTTP_RETRY_BASE_DELAY env or 1.0)

    Returns:
        Decorated function that retries on 429 and 5xx errors with exponential backoff

    Environment Variables:
        HTTP_RETRY_MAX_ATTEMPTS: Default max retries if not specified
        HTTP_RETRY_BASE_DELAY: Default base delay if not specified
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            retries, delay_base = _get_retry_params(max_retries, base_delay)
            last_exception = None
            response = None

            for attempt in range(retries + 1):
                try:
                    response = func(*args, **kwargs)

                    # Check if response needs retry
                    should_continue = _handle_retry_response(
                        response, attempt, retries, delay_base
                    )
                    if should_continue:
                        continue

                    # Success or non-retryable error
                    return response

                except httpx.RequestError as e:
                    last_exception = e
                    _handle_retry_exception(e, attempt, retries, delay_base)
                    continue

            # Exhausted all retries
            if last_exception:
                raise last_exception
            if response is not None:
                return response
            raise RuntimeError("No response received after retries")

        return wrapper

    return decorator


def get_http_client() -> httpx.Client:
    """
    Get a thread-local HTTP client with connection pooling.

    Returns a thread-local httpx.Client that reuses connections within the
    same thread, improving performance for multiple HTTP requests. Each thread
    gets its own client instance, making this thread-safe for concurrent use
    in web applications (FastAPI, Flask) and messaging systems.

    Returns:
        httpx.Client: Configured HTTP client with connection pooling

    Environment Variables:
        HTTP_TIMEOUT: Request timeout in seconds (default: 30.0)

    Note:
        - Thread-safe: Each thread gets its own client instance
        - The client uses default limits:
          - max_connections: 100
          - max_keepalive_connections: 20
          - keepalive_expiry: 5.0 seconds
        - Ideal for web frameworks and messaging applications where each
          request/message is handled in a separate thread
    """
    # Check if current thread already has a client
    if not hasattr(_thread_local, "client") or _thread_local.client is None:
        timeout = get_timeout()
        _thread_local.client = httpx.Client(
            verify=get_ssl_verify(),
            timeout=timeout,
            follow_redirects=True,
        )
    return _thread_local.client


def close_http_client() -> None:
    """
    Close the HTTP client for the current thread.

    This should be called when shutting down the application or cleaning up
    after request processing to properly release resources. In web frameworks,
    this can be called in teardown handlers or context managers.

    Note:
        This only closes the client for the current thread. Other threads
        maintain their own clients independently.
    """
    if hasattr(_thread_local, "client") and _thread_local.client is not None:
        _thread_local.client.close()
        _thread_local.client = None


def _reset_http_client() -> None:
    """
    Reset the HTTP client for the current thread (for testing purposes only).

    This function is intended for use in tests to clear the thread-local
    HTTP client instance. It should not be called in production code.
    """
    if hasattr(_thread_local, "client"):
        if _thread_local.client is not None:
            _thread_local.client.close()
        _thread_local.client = None


__all__ = [
    "_reset_http_client",
    "close_http_client",
    "get_http_client",
    "retry_with_backoff",
]
