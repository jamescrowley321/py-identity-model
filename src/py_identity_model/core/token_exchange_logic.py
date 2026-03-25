"""
Token Exchange business logic per RFC 8693.

Pure functions for preparing token exchange requests and processing responses.
"""

import httpx

from ..logging_config import logger
from ..logging_utils import redact_url
from .models import TokenExchangeRequest, TokenExchangeResponse


_TOKEN_EXCHANGE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"


def log_token_exchange_request(request: TokenExchangeRequest) -> None:
    """Log token exchange request."""
    logger.info(f"Exchanging token at {redact_url(request.address)}")
    logger.debug(
        f"Client ID: {request.client_id}, "
        f"Subject token type: {request.subject_token_type}"
    )


def prepare_token_exchange_request_data(
    request: TokenExchangeRequest,
) -> tuple[dict, dict, tuple[str, str] | None]:
    """Prepare request data, headers, and optional auth for token exchange.

    Returns:
        ``(data, headers, auth)`` where *auth* is ``None`` for public clients.
    """
    params: dict[str, str] = {
        "grant_type": _TOKEN_EXCHANGE_GRANT_TYPE,
        "subject_token": request.subject_token,
        "subject_token_type": request.subject_token_type,
        "client_id": request.client_id,
    }

    if request.actor_token is not None:
        params["actor_token"] = request.actor_token
    if request.actor_token_type is not None:
        params["actor_token_type"] = request.actor_token_type
    if request.resource is not None:
        params["resource"] = request.resource
    if request.audience is not None:
        params["audience"] = request.audience
    if request.scope is not None:
        params["scope"] = request.scope
    if request.requested_token_type is not None:
        params["requested_token_type"] = request.requested_token_type

    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    auth: tuple[str, str] | None = None
    if request.client_secret is not None:
        auth = (request.client_id, request.client_secret)

    return params, headers, auth


def process_token_exchange_response(
    response: httpx.Response,
) -> TokenExchangeResponse:
    """Process token exchange HTTP response."""
    logger.debug(f"Token exchange response status: {response.status_code}")

    if response.is_success:
        data = response.json()
        logger.info("Token exchange successful")
        return TokenExchangeResponse(
            is_successful=True,
            token=data,
            issued_token_type=data.get("issued_token_type"),
        )

    error_msg = (
        f"Token exchange failed with status code: "
        f"{response.status_code}. Response Content: {response.content}"
    )
    return TokenExchangeResponse(is_successful=False, error=error_msg)


def handle_token_exchange_error(e: Exception) -> TokenExchangeResponse:
    """Handle errors during token exchange requests."""
    if isinstance(e, httpx.RequestError):
        error_msg = f"Network error during token exchange: {e!s}"
        logger.error(error_msg, exc_info=True)
        return TokenExchangeResponse(is_successful=False, error=error_msg)

    error_msg = f"Unexpected error during token exchange: {e!s}"
    logger.error(error_msg, exc_info=True)
    return TokenExchangeResponse(is_successful=False, error=error_msg)


__all__ = [
    "handle_token_exchange_error",
    "log_token_exchange_request",
    "prepare_token_exchange_request_data",
    "process_token_exchange_response",
]
