"""
Token revocation business logic (RFC 7009).

Pure functions for preparing revocation requests and processing responses.
"""

import httpx

from ..logging_config import logger
from ..logging_utils import redact_url
from .error_handlers import handle_revocation_error
from .models import TokenRevocationRequest, TokenRevocationResponse


def log_revocation_request(request: TokenRevocationRequest) -> None:
    """Log token revocation request."""
    logger.info(f"Revoking token at {redact_url(request.address)}")
    logger.debug(f"Client ID: {request.client_id}")
    if request.token_type_hint:
        logger.debug(f"Token type hint: {request.token_type_hint}")


def prepare_revocation_request_data(
    request: TokenRevocationRequest,
) -> tuple[dict, dict, tuple[str, str] | None]:
    """Prepare request data, headers, and optional auth for revocation.

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


def process_revocation_response(
    response: httpx.Response,
) -> TokenRevocationResponse:
    """Process token revocation HTTP response.

    Per RFC 7009, a 200 response indicates success regardless of whether
    the token was valid.  No response body is expected.
    """
    logger.debug(f"Revocation response status: {response.status_code}")

    if response.is_success:
        logger.info("Token revocation successful")
        return TokenRevocationResponse(is_successful=True)

    try:
        error_msg = (
            f"Token revocation failed with status code: "
            f"{response.status_code}. Response Content: {response.content}"
        )
        return TokenRevocationResponse(is_successful=False, error=error_msg)
    except Exception as e:
        return handle_revocation_error(e)


__all__ = [
    "log_revocation_request",
    "prepare_revocation_request_data",
    "process_revocation_response",
]
