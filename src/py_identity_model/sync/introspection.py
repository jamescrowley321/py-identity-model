"""
Token introspection (synchronous implementation).

This module provides synchronous HTTP layer for OAuth 2.0 Token
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
from .http_client import get_http_client, retry_with_backoff
from .managed_client import HTTPClient


@retry_with_backoff()
def _introspect_token(
    client: httpx.Client,
    url: str,
    data: dict,
    headers: dict,
    auth: tuple[str, str] | None = None,
) -> httpx.Response:
    """Make introspection request with retry logic."""
    kwargs: dict = {"data": data, "headers": headers}
    if auth is not None:
        kwargs["auth"] = auth
    return client.post(url, **kwargs)


def introspect_token(
    request: TokenIntrospectionRequest,
    http_client: HTTPClient | None = None,
) -> TokenIntrospectionResponse:
    """Introspect an OAuth 2.0 token (RFC 7662).

    Args:
        request: Introspection request with token and client credentials.
        http_client: Optional managed HTTP client.

    Returns:
        TokenIntrospectionResponse with claims dict including ``active`` bool.
    """
    log_introspection_request(request)
    params, headers, auth = prepare_introspection_request_data(request)

    try:
        client = http_client.client if http_client else get_http_client()
        response = _introspect_token(
            client, request.address, params, headers, auth
        )
        result = process_introspection_response(response)
        response.close()
        return result
    except Exception as e:
        return handle_introspection_error(e)


__all__ = [
    "TokenIntrospectionRequest",
    "TokenIntrospectionResponse",
    "introspect_token",
]
