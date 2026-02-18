"""
Shared business logic for UserInfo endpoint operations.

This module contains the common processing logic used by both sync and async
UserInfo implementations, reducing code duplication.
"""

import httpx

from ..logging_config import logger
from ..logging_utils import redact_url
from .error_handlers import handle_userinfo_error
from .models import UserInfoRequest, UserInfoResponse
from .response_processors import parse_userinfo_response


def log_userinfo_request(request: UserInfoRequest) -> None:
    """Log UserInfo request."""
    logger.info(
        f"Requesting UserInfo from {redact_url(request.address)}",
    )


def log_userinfo_status(status_code: int) -> None:
    """Log UserInfo response status code."""
    logger.debug(f"UserInfo request status code: {status_code}")


def prepare_userinfo_headers(token: str) -> dict:
    """
    Prepare Authorization header for UserInfo request.

    Args:
        token: Bearer access token

    Returns:
        Headers dict with Authorization: Bearer <token>
    """
    return {"Authorization": f"Bearer {token}"}


def process_userinfo_response(response: httpx.Response) -> UserInfoResponse:
    """
    Process UserInfo response.

    Args:
        response: HTTP response from UserInfo endpoint

    Returns:
        UserInfoResponse with parsed claims, raw JWT, or error
    """
    log_userinfo_status(response.status_code)

    try:
        return parse_userinfo_response(response)
    except Exception as e:
        return handle_userinfo_error(e)


__all__ = [
    "log_userinfo_request",
    "log_userinfo_status",
    "prepare_userinfo_headers",
    "process_userinfo_response",
]
