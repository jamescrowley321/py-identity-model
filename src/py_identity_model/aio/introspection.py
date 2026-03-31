"""
Token introspection (asynchronous implementation).

This module provides asynchronous HTTP layer for OAuth 2.0 Token
Introspection (RFC 7662).
"""

import httpx

from ..core.error_handlers import handle_introspection_error
from ..core.introspection_logic import (
    log_introspection_request,
    prepare_introspection_request_data,
    process_introspection_response,
)
from ..core.models import TokenIntrospectionRequest, TokenIntrospectionResponse
from .http_client import get_async_http_client, retry_with_backoff_async
from .managed_client import AsyncHTTPClient


@retry_with_backoff_async()
async def _introspect_token(
    client: httpx.AsyncClient,
    url: str,
    data: dict,
    headers: dict,
    auth: tuple[str, str] | None = None,
) -> httpx.Response:
    """Make introspection request with retry logic (async)."""
    kwargs: dict = {"data": data, "headers": headers}
    if auth is not None:
        kwargs["auth"] = auth
    return await client.post(url, **kwargs)


async def introspect_token(
    request: TokenIntrospectionRequest,
    http_client: AsyncHTTPClient | None = None,
) -> TokenIntrospectionResponse:
    """Introspect an OAuth 2.0 token (RFC 7662, async).

    Args:
        request: Introspection request with token and client credentials.
        http_client: Optional managed HTTP client.

    Returns:
        TokenIntrospectionResponse with claims dict including ``active`` bool.
    """
    log_introspection_request(request)
    params, headers, auth = prepare_introspection_request_data(request)

    response = None
    try:
        client = http_client.client if http_client else get_async_http_client()
        response = await _introspect_token(
            client, request.address, params, headers, auth
        )
        return process_introspection_response(response)
    except Exception as e:
        return handle_introspection_error(e)
    finally:
        if response is not None:
            await response.aclose()


__all__ = [
    "TokenIntrospectionRequest",
    "TokenIntrospectionResponse",
    "introspect_token",
]
