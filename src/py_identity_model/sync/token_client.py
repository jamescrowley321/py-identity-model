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
from ..core.response_processors import parse_token_response
from ..http_client import get_http_client, retry_on_rate_limit
from ..logging_config import logger
from ..logging_utils import redact_url


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
    logger.info(
        f"Requesting client credentials token from {redact_url(request.address)}",
    )
    logger.debug(f"Client ID: {request.client_id}, Scope: {request.scope}")

    params = {"grant_type": "client_credentials", "scope": request.scope}

    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    try:
        client = get_http_client()
        response = _request_token(
            client,
            request.address,
            params,
            headers,
            (request.client_id, request.client_secret),
        )

        logger.debug(f"Token request status code: {response.status_code}")

        # Parse response using shared logic
        token_response = parse_token_response(response)

        if token_response.is_successful and token_response.token:
            logger.info("Client credentials token request successful")
            logger.debug(
                f"Token type: {token_response.token.get('token_type')}, "
                f"Expires in: {token_response.token.get('expires_in')} seconds",
            )

        return token_response

    except Exception as e:
        return handle_token_error(e)


__all__ = [
    "ClientCredentialsTokenRequest",
    "ClientCredentialsTokenResponse",
    "request_client_credentials_token",
]
