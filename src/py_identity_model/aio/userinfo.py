"""
UserInfo endpoint client (asynchronous implementation).

This module provides asynchronous HTTP layer for OpenID Connect UserInfo requests
per OIDC Core 1.0 Section 5.3.
"""

import httpx

from ..core.error_handlers import handle_userinfo_error
from ..core.models import UserInfoRequest, UserInfoResponse
from ..core.userinfo_logic import (
    log_userinfo_request,
    prepare_userinfo_headers,
    process_userinfo_response,
    validate_userinfo_sub,
)
from .http_client import get_async_http_client, retry_with_backoff_async
from .managed_client import AsyncHTTPClient


@retry_with_backoff_async()
async def _request_userinfo(
    client: httpx.AsyncClient,
    url: str,
    headers: dict,
) -> httpx.Response:
    """
    Request UserInfo with retry logic.

    Automatically retries on 429 (rate limiting) and 5xx errors with
    exponential backoff. Configuration is read from environment variables.
    """
    return await client.get(url, headers=headers)


async def get_userinfo(
    request: UserInfoRequest,
    http_client: AsyncHTTPClient | None = None,
) -> UserInfoResponse:
    """
    Get claims about an authenticated user from the UserInfo endpoint (async).

    Args:
        request: UserInfo request with endpoint address and access token
        http_client: Optional managed HTTP client.  When ``None``, uses the
            module-level singleton.

    Returns:
        UserInfoResponse: Response with claims (JSON) or raw JWT string
    """
    log_userinfo_request(request)
    headers = prepare_userinfo_headers(request.token)

    response = None
    try:
        client = http_client.client if http_client else get_async_http_client()
        response = await _request_userinfo(client, request.address, headers)
        result = process_userinfo_response(response)
        return validate_userinfo_sub(result, request.expected_sub)
    except Exception as e:
        return handle_userinfo_error(e)
    finally:
        if response is not None:
            await response.aclose()


__all__ = [
    "UserInfoRequest",
    "UserInfoResponse",
    "get_userinfo",
]
