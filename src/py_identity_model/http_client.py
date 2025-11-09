"""
HTTP client configuration with connection pooling.

This module provides shared HTTP clients with connection pooling to improve
performance when making multiple HTTP requests.
"""

from functools import lru_cache

import httpx

from .ssl_config import get_ssl_verify


@lru_cache(maxsize=1)
def get_http_client() -> httpx.Client:
    """
    Get a persistent HTTP client with connection pooling.

    Returns a singleton httpx.Client that reuses connections, improving
    performance for multiple HTTP requests. The client is cached so that
    all parts of the application share the same connection pool.

    Returns:
        httpx.Client: Configured HTTP client with connection pooling

    Note:
        The client uses default limits:
        - max_connections: 100
        - max_keepalive_connections: 20
        - keepalive_expiry: 5.0 seconds

        These defaults work well for most applications. For high-throughput
        applications, consider increasing max_connections.
    """
    return httpx.Client(
        verify=get_ssl_verify(),
        timeout=30.0,
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


__all__ = ["close_http_client", "get_http_client"]
