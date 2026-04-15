"""
Shared HTTP utilities for retry logic and configuration.

This module provides common utilities used by both sync and async HTTP clients.

Environment Variables:
    HTTP_RETRY_MAX_ATTEMPTS: Maximum number of retry attempts (default: 3)
    HTTP_RETRY_BASE_DELAY: Base delay in seconds for exponential backoff (default: 1.0)
    HTTP_TIMEOUT: Request timeout in seconds (default: 30.0)
"""

import os

import httpx

from ..exceptions import NetworkException


# Default HTTP configuration constants
DEFAULT_HTTP_TIMEOUT = 30.0
DEFAULT_RETRY_MAX_ATTEMPTS = 3
DEFAULT_RETRY_BASE_DELAY = 1.0
DEFAULT_MAX_JWKS_SIZE = 512 * 1024  # 512 KB
DEFAULT_MAX_JWKS_KEYS = 100

# HTTP status codes for retry logic
HTTP_TOO_MANY_REQUESTS = 429
HTTP_INTERNAL_SERVER_ERROR = 500
HTTP_REDIRECT_MIN = 300
HTTP_REDIRECT_MAX = 399


def get_retry_config() -> tuple[int, float]:
    """
    Get retry configuration from environment variables.

    Returns:
        tuple: (max_retries, base_delay)
    """
    max_retries = int(
        os.getenv("HTTP_RETRY_MAX_ATTEMPTS", str(DEFAULT_RETRY_MAX_ATTEMPTS))
    )
    base_delay = float(
        os.getenv("HTTP_RETRY_BASE_DELAY", str(DEFAULT_RETRY_BASE_DELAY))
    )
    return max_retries, base_delay


def get_timeout() -> float:
    """
    Get HTTP timeout from environment variable.

    Returns:
        float: Timeout in seconds
    """
    return float(os.getenv("HTTP_TIMEOUT", str(DEFAULT_HTTP_TIMEOUT)))


def should_retry_response(response: httpx.Response, attempt: int, retries: int) -> bool:
    """
    Check if response should be retried.

    Args:
        response: HTTP response to check
        attempt: Current attempt number (0-indexed)
        retries: Maximum number of retries

    Returns:
        bool: True if should retry, False otherwise
    """
    return (
        response.status_code == HTTP_TOO_MANY_REQUESTS
        or response.status_code >= HTTP_INTERNAL_SERVER_ERROR
    ) and attempt < retries


def calculate_delay(base_delay: float, attempt: int) -> float:
    """
    Calculate exponential backoff delay.

    Args:
        base_delay: Base delay in seconds
        attempt: Current attempt number (0-indexed)

    Returns:
        float: Delay in seconds
    """
    return base_delay * (2**attempt)


def check_no_redirect(response: httpx.Response) -> None:
    """Raise if the response is a redirect (3xx).

    Redirect following is disabled to prevent SSRF attacks where an
    attacker-controlled server redirects requests to internal resources.
    """
    if HTTP_REDIRECT_MIN <= response.status_code <= HTTP_REDIRECT_MAX:
        location = response.headers.get("location", "<not provided>")
        raise NetworkException(
            f"HTTP {response.status_code} redirect blocked — "
            f"target: '{location}'. Redirect following is disabled "
            f"to prevent SSRF attacks.",
            url=str(response.url),
            status_code=response.status_code,
        )


def get_max_jwks_size() -> int:
    """Get maximum JWKS response size from environment variable.

    Returns:
        int: Maximum response size in bytes.
    """
    return int(os.getenv("MAX_JWKS_SIZE", str(DEFAULT_MAX_JWKS_SIZE)))


def get_max_jwks_keys() -> int:
    """Get maximum number of keys allowed in a JWKS response.

    Returns:
        int: Maximum number of keys.
    """
    return int(os.getenv("MAX_JWKS_KEYS", str(DEFAULT_MAX_JWKS_KEYS)))


__all__ = [
    "DEFAULT_HTTP_TIMEOUT",
    "DEFAULT_MAX_JWKS_KEYS",
    "DEFAULT_MAX_JWKS_SIZE",
    "DEFAULT_RETRY_BASE_DELAY",
    "DEFAULT_RETRY_MAX_ATTEMPTS",
    "HTTP_INTERNAL_SERVER_ERROR",
    "HTTP_REDIRECT_MAX",
    "HTTP_REDIRECT_MIN",
    "HTTP_TOO_MANY_REQUESTS",
    "calculate_delay",
    "check_no_redirect",
    "get_max_jwks_keys",
    "get_max_jwks_size",
    "get_retry_config",
    "get_timeout",
    "should_retry_response",
]
