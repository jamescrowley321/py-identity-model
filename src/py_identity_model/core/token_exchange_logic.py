"""
Token Exchange business logic per RFC 8693.

Pure functions for preparing token exchange requests and processing responses.
"""

import json

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


def _validate_request_params(request: TokenExchangeRequest) -> None:
    """Validate token exchange request parameters.

    Raises:
        ValueError: If ``actor_token`` is set without ``actor_token_type``
            (RFC 8693 §2.1) or if required/optional fields are empty strings.
    """
    # M2: RFC 8693 §2.1 — actor_token_type REQUIRED when actor_token present
    if request.actor_token is not None and request.actor_token_type is None:
        raise ValueError(
            "actor_token_type is REQUIRED when actor_token is provided "
            "(RFC 8693 Section 2.1)"
        )

    # S2: Reject empty strings on required fields
    if not request.subject_token:
        raise ValueError("subject_token must not be empty")
    if not request.subject_token_type:
        raise ValueError("subject_token_type must not be empty")

    # S2: Reject empty strings on optional fields when provided
    if request.actor_token is not None and not request.actor_token:
        raise ValueError("actor_token must not be empty when provided")
    if request.actor_token_type is not None and not request.actor_token_type:
        raise ValueError("actor_token_type must not be empty when provided")


def prepare_token_exchange_request_data(
    request: TokenExchangeRequest,
) -> tuple[dict, dict, tuple[str, str] | None]:
    """Prepare request data, headers, and optional auth for token exchange.

    Returns:
        ``(data, headers, auth)`` where *auth* is ``None`` for public clients.

    Raises:
        ValueError: If ``actor_token`` is set without ``actor_token_type``
            (RFC 8693 §2.1) or if required fields are empty strings.
    """
    _validate_request_params(request)

    params: dict[str, str] = {
        "grant_type": _TOKEN_EXCHANGE_GRANT_TYPE,
        "subject_token": request.subject_token,
        "subject_token_type": request.subject_token_type,
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

    # M1: RFC 6749 §2.3.1 — client_id excluded from body when using Basic Auth
    auth: tuple[str, str] | None = None
    if request.client_secret:
        auth = (request.client_id, request.client_secret)
    else:
        params["client_id"] = request.client_id

    return params, headers, auth


def process_token_exchange_response(
    response: httpx.Response,
) -> TokenExchangeResponse:
    """Process token exchange HTTP response."""
    logger.debug(f"Token exchange response status: {response.status_code}")

    if response.is_success:
        # S3: Guard against non-JSON and non-dict responses
        try:
            data = response.json()
        except (json.JSONDecodeError, ValueError):
            error_msg = "Token exchange response has invalid JSON body"
            logger.error(error_msg)
            return TokenExchangeResponse(is_successful=False, error=error_msg)

        if not isinstance(data, dict):
            error_msg = (
                f"Token exchange response is not a JSON object: "
                f"{type(data).__name__}"
            )
            logger.error(error_msg)
            return TokenExchangeResponse(is_successful=False, error=error_msg)

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
