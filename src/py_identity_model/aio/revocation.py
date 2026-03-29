"""
Token revocation (asynchronous implementation).

This module provides asynchronous HTTP layer for OAuth 2.0 Token
Revocation (RFC 7009).
"""

import httpx

from ..core.error_handlers import handle_revocation_error
from ..core.models import TokenRevocationRequest, TokenRevocationResponse
from ..core.revocation_logic import (
    log_revocation_request,
    prepare_revocation_request_data,
    process_revocation_response,
)
from .http_client import get_async_http_client, retry_with_backoff_async
from .managed_client import AsyncHTTPClient


@retry_with_backoff_async()
async def _revoke_token(
    client: httpx.AsyncClient,
    url: str,
    data: dict,
    headers: dict,
    auth: tuple[str, str] | None = None,
) -> httpx.Response:
    """Make revocation request with retry logic (async)."""
    kwargs: dict = {"data": data, "headers": headers}
    if auth is not None:
        kwargs["auth"] = auth
    return await client.post(url, **kwargs)


async def revoke_token(
    request: TokenRevocationRequest,
    http_client: AsyncHTTPClient | None = None,
) -> TokenRevocationResponse:
    """Revoke an OAuth 2.0 token (RFC 7009, async).

    Args:
        request: Revocation request with token and client credentials.
        http_client: Optional managed HTTP client.

    Returns:
        TokenRevocationResponse indicating success or error.
    """
    log_revocation_request(request)
    params, headers, auth = prepare_revocation_request_data(request)

    response = None
    try:
        client = http_client.client if http_client else get_async_http_client()
        response = await _revoke_token(
            client, request.address, params, headers, auth
        )
        return process_revocation_response(response)
    except Exception as e:
        return handle_revocation_error(e)
    finally:
        if response is not None:
            await response.aclose()


__all__ = [
    "TokenRevocationRequest",
    "TokenRevocationResponse",
    "revoke_token",
]
