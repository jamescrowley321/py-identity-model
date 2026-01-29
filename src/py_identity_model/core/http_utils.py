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


# Default HTTP configuration constants
DEFAULT_HTTP_TIMEOUT = 30.0
DEFAULT_RETRY_MAX_ATTEMPTS = 3
DEFAULT_RETRY_BASE_DELAY = 1.0


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


def should_retry_response(
    response: httpx.Response, attempt: int, retries: int
) -> bool:
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
        response.status_code == 429 or response.status_code >= 500
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


__all__ = [
    "DEFAULT_HTTP_TIMEOUT",
    "DEFAULT_RETRY_BASE_DELAY",
    "DEFAULT_RETRY_MAX_ATTEMPTS",
    "calculate_delay",
    "get_retry_config",
    "get_timeout",
    "should_retry_response",
]
