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
)
from .http_client import get_async_http_client, retry_with_backoff_async


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


async def get_userinfo(request: UserInfoRequest) -> UserInfoResponse:
    """
    Get claims about an authenticated user from the UserInfo endpoint (async).

    Args:
        request: UserInfo request with endpoint address and access token

    Returns:
        UserInfoResponse: Response with claims (JSON) or raw JWT string
    """
    log_userinfo_request(request)
    headers = prepare_userinfo_headers(request.token)

    try:
        client = get_async_http_client()
        response = await _request_userinfo(client, request.address, headers)
        return process_userinfo_response(response)
    except Exception as e:
        return handle_userinfo_error(e)


__all__ = [
    "UserInfoRequest",
    "UserInfoResponse",
    "get_userinfo",
]
