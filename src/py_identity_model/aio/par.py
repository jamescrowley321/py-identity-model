"""
Pushed Authorization Requests (asynchronous implementation, RFC 9126).
"""

import httpx

from ..core.error_handlers import handle_par_error
from ..core.models import (
    PushedAuthorizationRequest,
    PushedAuthorizationResponse,
)
from ..core.par_logic import (
    log_par_request,
    prepare_par_request_data,
    process_par_response,
)
from .http_client import get_async_http_client, retry_with_backoff_async
from .managed_client import AsyncHTTPClient


@retry_with_backoff_async()
async def _push_authorization_request(
    client: httpx.AsyncClient,
    url: str,
    data: dict,
    headers: dict,
    auth: tuple[str, str] | None = None,
) -> httpx.Response:
    """Make PAR request with retry logic (async)."""
    kwargs: dict = {"data": data, "headers": headers}
    if auth is not None:
        kwargs["auth"] = auth
    return await client.post(url, **kwargs)


async def push_authorization_request(
    request: PushedAuthorizationRequest,
    http_client: AsyncHTTPClient | None = None,
) -> PushedAuthorizationResponse:
    """Push authorization parameters to the PAR endpoint (RFC 9126, async).

    Args:
        request: PAR request with authorization parameters.
        http_client: Optional managed HTTP client.

    Returns:
        PushedAuthorizationResponse with ``request_uri`` and ``expires_in``.
    """
    log_par_request(request)

    response = None
    try:
        params, headers, auth = prepare_par_request_data(request)
        client = http_client.client if http_client else get_async_http_client()
        response = await _push_authorization_request(
            client, request.address, params, headers, auth
        )
        return process_par_response(response)
    except Exception as e:
        return handle_par_error(e)
    finally:
        if response is not None:
            await response.aclose()


__all__ = [
    "PushedAuthorizationRequest",
    "PushedAuthorizationResponse",
    "push_authorization_request",
]
