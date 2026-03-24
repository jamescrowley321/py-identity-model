"""
Token client (synchronous implementation).

This module provides synchronous HTTP layer for OAuth 2.0 token requests.
"""

import httpx

from ..core.error_handlers import (
    handle_auth_code_token_error,
    handle_token_error,
)
from ..core.models import (
    AuthorizationCodeTokenRequest,
    AuthorizationCodeTokenResponse,
    ClientCredentialsTokenRequest,
    ClientCredentialsTokenResponse,
)
from ..core.token_client_logic import (
    log_auth_code_token_request,
    log_token_request,
    prepare_auth_code_token_request_data,
    prepare_token_request_data,
    process_auth_code_token_response,
    process_token_response,
)
from .http_client import get_http_client, retry_with_backoff
from .managed_client import HTTPClient


@retry_with_backoff()
def _request_token(
    client: httpx.Client,
    url: str,
    data: dict,
    headers: dict,
    auth: tuple[str, str],
) -> httpx.Response:
    """
    Request token with retry logic.

    Automatically retries on 429 (rate limiting) and 5xx errors with
    exponential backoff. Configuration is read from environment variables.
    """
    return client.post(url, data=data, headers=headers, auth=auth)


def request_client_credentials_token(
    request: ClientCredentialsTokenRequest,
    http_client: HTTPClient | None = None,
) -> ClientCredentialsTokenResponse:
    """
    Request an access token using client credentials flow.

    Args:
        request: Client credentials token request
        http_client: Optional managed HTTP client.  When ``None``, uses the
            thread-local default.

    Returns:
        ClientCredentialsTokenResponse: Token response
    """
    log_token_request(request)
    params, headers = prepare_token_request_data(request)

    try:
        client = http_client.client if http_client else get_http_client()
        response = _request_token(
            client,
            request.address,
            params,
            headers,
            (request.client_id, request.client_secret),
        )
        result = process_token_response(response)
        # Explicitly close the response to ensure the connection is released
        response.close()
        return result
    except Exception as e:
        return handle_token_error(e)


def request_authorization_code_token(
    request: AuthorizationCodeTokenRequest,
    http_client: HTTPClient | None = None,
) -> AuthorizationCodeTokenResponse:
    """Exchange an authorization code for tokens.

    Args:
        request: Authorization code token exchange request.
        http_client: Optional managed HTTP client.

    Returns:
        AuthorizationCodeTokenResponse with token dict or error.
    """
    log_auth_code_token_request(request)
    params, headers, auth = prepare_auth_code_token_request_data(request)

    try:
        client = http_client.client if http_client else get_http_client()
        response = _request_token(
            client, request.address, params, headers, auth or ("", "")
        )
        result = process_auth_code_token_response(response)
        response.close()
        return result
    except Exception as e:
        return handle_auth_code_token_error(e)


__all__ = [
    "AuthorizationCodeTokenRequest",
    "AuthorizationCodeTokenResponse",
    "ClientCredentialsTokenRequest",
    "ClientCredentialsTokenResponse",
    "request_authorization_code_token",
    "request_client_credentials_token",
]
