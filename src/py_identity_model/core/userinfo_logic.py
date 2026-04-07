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


def validate_userinfo_sub(
    response: UserInfoResponse,
    expected_sub: str | None,
) -> UserInfoResponse:
    """Validate that the UserInfo ``sub`` matches the ID token ``sub``.

    Per OIDC Core 1.0 Section 5.3.4, the ``sub`` claim in the UserInfo
    response MUST exactly match the ``sub`` in the ID token.

    Args:
        response: A parsed UserInfo response.
        expected_sub: The ``sub`` from the caller's ID token.  When
            ``None``, validation is skipped (opt-in).

    Returns:
        The original response when validation passes or is skipped,
        otherwise an error ``UserInfoResponse``.
    """
    # Skip validation when not requested, on failure, or for JWT responses
    if expected_sub is None or not response.is_successful or response.raw is not None:
        return response

    claims = object.__getattribute__(response, "claims")
    if claims is None:
        return UserInfoResponse(
            is_successful=False,
            error="UserInfo response contains no claims to validate sub against",
        )

    actual_sub = claims.get("sub")
    if actual_sub is None:
        return UserInfoResponse(
            is_successful=False,
            error="UserInfo response is missing required 'sub' claim",
        )

    if actual_sub != expected_sub:
        return UserInfoResponse(
            is_successful=False,
            error=(
                f"UserInfo sub mismatch: expected '{expected_sub}', got '{actual_sub}'"
            ),
        )

    return response


__all__ = [
    "log_userinfo_request",
    "log_userinfo_status",
    "prepare_userinfo_headers",
    "process_userinfo_response",
    "validate_userinfo_sub",
]
