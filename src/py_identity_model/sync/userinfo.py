"""
UserInfo endpoint client (synchronous implementation).

This module provides synchronous HTTP layer for OpenID Connect UserInfo requests
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
from .http_client import get_http_client, retry_with_backoff
from .managed_client import HTTPClient


@retry_with_backoff()
def _request_userinfo(
    client: httpx.Client,
    url: str,
    headers: dict,
) -> httpx.Response:
    """
    Request UserInfo with retry logic.

    Automatically retries on 429 (rate limiting) and 5xx errors with
    exponential backoff. Configuration is read from environment variables.
    """
    return client.get(url, headers=headers)


def get_userinfo(
    request: UserInfoRequest,
    http_client: HTTPClient | None = None,
) -> UserInfoResponse:
    """
    Get claims about an authenticated user from the UserInfo endpoint.

    Args:
        request: UserInfo request with endpoint address and access token
        http_client: Optional managed HTTP client.  When ``None``, uses the
            thread-local default.

    Returns:
        UserInfoResponse: Response with claims (JSON) or raw JWT string
    """
    log_userinfo_request(request)
    headers = prepare_userinfo_headers(request.token)

    response = None
    try:
        client = http_client.client if http_client else get_http_client()
        response = _request_userinfo(client, request.address, headers)
        return process_userinfo_response(response)
    except Exception as e:
        return handle_userinfo_error(e)
    finally:
        if response is not None:
            response.close()


__all__ = [
    "UserInfoRequest",
    "UserInfoResponse",
    "get_userinfo",
]
