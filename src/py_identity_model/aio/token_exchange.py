"""
Token Exchange (asynchronous implementation, RFC 8693).
"""

from ..core.models import TokenExchangeRequest, TokenExchangeResponse
from ..core.token_exchange_logic import (
    handle_token_exchange_error,
    log_token_exchange_request,
    prepare_token_exchange_request_data,
    process_token_exchange_response,
)
from .http_client import get_async_http_client, retry_with_backoff_async
from .managed_client import AsyncHTTPClient


@retry_with_backoff_async()
async def _exchange_token(client, url, data, headers, auth=None):
    """Make token exchange request with retry logic (async)."""
    kwargs: dict = {"data": data, "headers": headers}
    if auth is not None:
        kwargs["auth"] = auth
    return await client.post(url, **kwargs)


async def exchange_token(
    request: TokenExchangeRequest,
    http_client: AsyncHTTPClient | None = None,
) -> TokenExchangeResponse:
    """Exchange a token using OAuth 2.0 Token Exchange (RFC 8693, async).

    Args:
        request: Token exchange request with subject token and parameters.
        http_client: Optional managed HTTP client.

    Returns:
        TokenExchangeResponse with exchanged ``token`` and
        ``issued_token_type``.
    """
    log_token_exchange_request(request)

    response = None
    try:
        params, headers, auth = prepare_token_exchange_request_data(request)
        client = http_client.client if http_client else get_async_http_client()
        response = await _exchange_token(
            client, request.address, params, headers, auth
        )
        return process_token_exchange_response(response)
    except Exception as e:
        return handle_token_exchange_error(e)
    finally:
        if response is not None:
            await response.aclose()


__all__ = [
    "TokenExchangeRequest",
    "TokenExchangeResponse",
    "exchange_token",
]
