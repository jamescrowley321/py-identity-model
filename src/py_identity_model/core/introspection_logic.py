"""
Token introspection business logic (RFC 7662).

Pure functions for preparing introspection requests and processing responses.
Used by both sync and async implementations.
"""

import httpx

from ..logging_config import logger
from ..logging_utils import redact_url
from .error_handlers import handle_introspection_error
from .models import TokenIntrospectionRequest, TokenIntrospectionResponse
from .response_processors import parse_introspection_response


def log_introspection_request(request: TokenIntrospectionRequest) -> None:
    """Log token introspection request."""
    logger.info(f"Introspecting token at {redact_url(request.address)}")
    logger.debug(f"Client ID: {request.client_id}")
    if request.token_type_hint is not None:
        logger.debug(f"Token type hint: {request.token_type_hint}")


def prepare_introspection_request_data(
    request: TokenIntrospectionRequest,
) -> tuple[dict, dict, tuple[str, str] | None]:
    """Prepare request data, headers, and optional auth for introspection.

    Returns:
        ``(data, headers, auth)`` where *auth* is ``None`` for public clients.
    """
    params: dict[str, str] = {"token": request.token}
    if request.token_type_hint is not None:
        params["token_type_hint"] = request.token_type_hint

    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    auth: tuple[str, str] | None = None
    if request.client_secret is not None:
        auth = (request.client_id, request.client_secret)
    else:
        params["client_id"] = request.client_id

    return params, headers, auth


def log_introspection_status(status_code: int) -> None:
    """Log introspection response status code."""
    logger.debug(f"Introspection response status: {status_code}")


def process_introspection_response(
    response: httpx.Response,
) -> TokenIntrospectionResponse:
    """Process token introspection HTTP response."""
    log_introspection_status(response.status_code)

    try:
        result = parse_introspection_response(response)
        if result.is_successful and result.claims is not None:
            active = result.claims.get("active", False)
            logger.info(f"Token introspection complete: active={active}")
        return result
    except Exception as e:
        return handle_introspection_error(e)


__all__ = [
    "log_introspection_request",
    "prepare_introspection_request_data",
    "process_introspection_response",
]
