"""
Shared business logic for token client operations.

This module contains the common processing logic used by both sync and async
token client implementations, reducing code duplication.
"""

import httpx

from ..logging_config import logger
from ..logging_utils import redact_url
from .error_handlers import handle_token_error
from .models import (
    ClientCredentialsTokenRequest,
    ClientCredentialsTokenResponse,
)
from .response_processors import parse_token_response


def log_token_request(request: ClientCredentialsTokenRequest) -> None:
    """Log token request."""
    logger.info(
        f"Requesting client credentials token from {redact_url(request.address)}",
    )
    logger.debug(f"Client ID: {request.client_id}, Scope: {request.scope}")


def log_token_status(status_code: int) -> None:
    """Log token response status code."""
    logger.debug(f"Token request status code: {status_code}")


def log_token_success(token_response: ClientCredentialsTokenResponse) -> None:
    """Log successful token fetch."""
    if token_response.is_successful and token_response.token:
        logger.info("Client credentials token request successful")
        logger.debug(
            f"Token type: {token_response.token.get('token_type')}, "
            f"Expires in: {token_response.token.get('expires_in')} seconds",
        )


def prepare_token_request_data(
    request: ClientCredentialsTokenRequest,
) -> tuple[dict, dict]:
    """
    Prepare request data and headers for token request.

    Args:
        request: Client credentials token request

    Returns:
        Tuple of (data dict, headers dict)
    """
    params = {"grant_type": "client_credentials", "scope": request.scope}
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    return params, headers


def process_token_response(
    response: httpx.Response,
) -> ClientCredentialsTokenResponse:
    """
    Process token response.

    Args:
        response: HTTP response from token endpoint

    Returns:
        ClientCredentialsTokenResponse with parsed token or error
    """
    log_token_status(response.status_code)

    try:
        # Parse response using shared logic
        token_response = parse_token_response(response)
        log_token_success(token_response)
        return token_response
    except Exception as e:
        return handle_token_error(e)
