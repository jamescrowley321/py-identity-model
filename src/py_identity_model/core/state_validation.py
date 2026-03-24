"""
State parameter validation for OAuth 2.0 / OpenID Connect authorization callbacks.

Provides constant-time comparison of the ``state`` parameter to prevent
CSRF attacks on authorization callbacks (RFC 6749 Section 10.12).
"""

from dataclasses import dataclass
from enum import Enum
import hmac

from .authorize_response import AuthorizeCallbackResponse


class AuthorizeCallbackValidationResult(Enum):
    """Outcome of authorization callback state validation."""

    SUCCESS = "success"
    STATE_MISMATCH = "state_mismatch"
    MISSING_STATE = "missing_state"
    ERROR_RESPONSE = "error_response"


@dataclass
class StateValidationResult:
    """Result of validating the ``state`` parameter in an authorization callback."""

    is_valid: bool
    result: AuthorizeCallbackValidationResult
    error: str | None = None
    error_description: str | None = None


def validate_authorize_callback_state(
    response: AuthorizeCallbackResponse,
    expected_state: str,
) -> StateValidationResult:
    """Validate the ``state`` parameter from an authorization callback.

    Checks are performed in priority order:

    1. **Error response** — if the authorization server returned an error,
       validation fails with ``ERROR_RESPONSE``.
    2. **Missing state** — if the callback contains no ``state`` parameter,
       validation fails with ``MISSING_STATE``.
    3. **State mismatch** — the received state is compared to
       *expected_state* using ``hmac.compare_digest`` (constant-time) to
       avoid timing side-channels.

    Args:
        response: A parsed ``AuthorizeCallbackResponse``.
        expected_state: The ``state`` value sent in the original
            authorization request.

    Returns:
        A ``StateValidationResult`` indicating whether validation passed.
    """
    if not response.is_successful:
        return StateValidationResult(
            is_valid=False,
            result=AuthorizeCallbackValidationResult.ERROR_RESPONSE,
            error=response.error,
            error_description=response.error_description,
        )

    if response.state is None:
        return StateValidationResult(
            is_valid=False,
            result=AuthorizeCallbackValidationResult.MISSING_STATE,
            error="missing_state",
            error_description="State parameter not present in callback",
        )

    if not hmac.compare_digest(response.state, expected_state):
        return StateValidationResult(
            is_valid=False,
            result=AuthorizeCallbackValidationResult.STATE_MISMATCH,
            error="state_mismatch",
            error_description="State parameter does not match expected value",
        )

    return StateValidationResult(
        is_valid=True,
        result=AuthorizeCallbackValidationResult.SUCCESS,
    )


__all__ = [
    "AuthorizeCallbackValidationResult",
    "StateValidationResult",
    "validate_authorize_callback_state",
]
