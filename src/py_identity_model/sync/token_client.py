"""
Token client (synchronous implementation).

This module provides synchronous HTTP layer for OAuth 2.0 token requests.
"""

import httpx

from ..core.error_handlers import handle_token_error
from ..core.models import (
    ClientCredentialsTokenRequest,
    ClientCredentialsTokenResponse,
)
from ..core.token_client_logic import (
    log_token_request,
    prepare_token_request_data,
    process_token_response,
)
from ..http_client import get_http_client, retry_on_rate_limit


@retry_on_rate_limit()
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
) -> ClientCredentialsTokenResponse:
    """
    Request an access token using client credentials flow.

    Args:
        request: Client credentials token request

    Returns:
        ClientCredentialsTokenResponse: Token response
    """
    log_token_request(request)
    params, headers = prepare_token_request_data(request)

    try:
        client = get_http_client()
        response = _request_token(
            client,
            request.address,
            params,
            headers,
            (request.client_id, request.client_secret),
        )
        return process_token_response(response)
    except Exception as e:
        return handle_token_error(e)


__all__ = [
    "ClientCredentialsTokenRequest",
    "ClientCredentialsTokenResponse",
    "request_client_credentials_token",
]
