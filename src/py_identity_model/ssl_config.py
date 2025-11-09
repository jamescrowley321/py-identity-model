"""
SSL certificate configuration utilities.

This module provides backward compatibility for SSL certificate environment variables
when migrating from requests to httpx.
"""

from functools import lru_cache
import os
from threading import Lock


# Thread safety lock for SSL configuration
_ssl_lock = Lock()


def ensure_ssl_compatibility() -> None:
    """
    Ensure backward compatibility for SSL certificate environment variables.

    httpx respects SSL_CERT_FILE and CURL_CA_BUNDLE, but not REQUESTS_CA_BUNDLE
    (which was used by the requests library). For backward compatibility, if
    REQUESTS_CA_BUNDLE is set but SSL_CERT_FILE is not, we set SSL_CERT_FILE
    to the value of REQUESTS_CA_BUNDLE.

    This function is called automatically when the library is imported, so users
    don't need to call it explicitly.

    Environment variables checked (in priority order):
    1. SSL_CERT_FILE - httpx native variable (highest priority)
    2. CURL_CA_BUNDLE - also respected by httpx
    3. REQUESTS_CA_BUNDLE - legacy requests library variable (for backward compatibility)
    """
    # Only set SSL_CERT_FILE if it's not already set
    if "SSL_CERT_FILE" not in os.environ:
        # Check CURL_CA_BUNDLE first (also respected by httpx)
        if "CURL_CA_BUNDLE" in os.environ:
            # CURL_CA_BUNDLE is already set and httpx will use it
            pass
        # Then check REQUESTS_CA_BUNDLE for backward compatibility
        elif "REQUESTS_CA_BUNDLE" in os.environ:
            # Set SSL_CERT_FILE to REQUESTS_CA_BUNDLE value for httpx to use
            os.environ["SSL_CERT_FILE"] = os.environ["REQUESTS_CA_BUNDLE"]


@lru_cache(maxsize=1)
def get_ssl_verify() -> str | bool:
    """
    Get SSL verification configuration for httpx with full backward compatibility.

    This function is thread-safe and cached for performance. It checks environment
    variables in priority order and returns the appropriate value for httpx's
    verify parameter.

    Environment variables checked (in priority order):
    1. SSL_CERT_FILE - standard environment variable (highest priority)
    2. CURL_CA_BUNDLE - used by curl and httpx
    3. REQUESTS_CA_BUNDLE - legacy requests library (for backward compatibility)

    Returns:
        str: Path to CA bundle file if any environment variable is set
        bool: True for default system CA verification

    Note:
        Result is cached using @lru_cache. If environment variables change at
        runtime, call get_ssl_verify.cache_clear() to refresh.

    Thread Safety:
        This function is thread-safe and can be called from multiple threads
        concurrently in web applications (FastAPI, Flask, Django).

    Examples:
        >>> # Use in httpx client
        >>> async with httpx.AsyncClient(verify=get_ssl_verify()) as client:
        ...     response = await client.get(url)

        >>> # Synchronous usage
        >>> response = httpx.get(url, verify=get_ssl_verify())
    """
    with _ssl_lock:
        for env_var in [
            "SSL_CERT_FILE",
            "CURL_CA_BUNDLE",
            "REQUESTS_CA_BUNDLE",
        ]:
            if os.environ.get(env_var):
                return os.environ[env_var]
        return True  # Default: verify with system CA bundle


# Initialize SSL compatibility when module is imported
ensure_ssl_compatibility()


__all__ = ["ensure_ssl_compatibility", "get_ssl_verify"]
