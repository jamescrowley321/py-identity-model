"""
Pushed Authorization Request (PAR) business logic per RFC 9126.

Pure functions for preparing PAR requests and processing responses.
"""

import httpx

from ..logging_config import logger
from ..logging_utils import redact_url
from .error_handlers import handle_par_error
from .models import PushedAuthorizationRequest, PushedAuthorizationResponse


def log_par_request(request: PushedAuthorizationRequest) -> None:
    """Log pushed authorization request."""
    logger.info(
        f"Pushing authorization request to {redact_url(request.address)}"
    )
    logger.debug(f"Client ID: {request.client_id}")


def prepare_par_request_data(
    request: PushedAuthorizationRequest,
) -> tuple[dict, dict, tuple[str, str] | None]:
    """Prepare request data, headers, and optional auth for PAR.

    Returns:
        ``(data, headers, auth)`` where *auth* is ``None`` for public clients.
    """
    if (request.code_challenge is None) != (
        request.code_challenge_method is None
    ):
        raise ValueError(
            "code_challenge and code_challenge_method must both be set or both be absent"
        )

    params: dict[str, str] = {
        "redirect_uri": request.redirect_uri,
        "scope": request.scope,
        "response_type": request.response_type,
    }
    if request.state is not None:
        params["state"] = request.state
    if request.nonce is not None:
        params["nonce"] = request.nonce
    if request.code_challenge is not None:
        params["code_challenge"] = request.code_challenge
    if request.code_challenge_method is not None:
        params["code_challenge_method"] = request.code_challenge_method

    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    auth: tuple[str, str] | None = None
    if request.client_secret is not None:
        auth = (request.client_id, request.client_secret)
    else:
        params["client_id"] = request.client_id

    return params, headers, auth


def process_par_response(
    response: httpx.Response,
) -> PushedAuthorizationResponse:
    """Process PAR HTTP response."""
    logger.debug(f"PAR response status: {response.status_code}")

    if response.is_success:
        data = response.json()
        request_uri = data.get("request_uri")
        expires_in = data.get("expires_in")
        if not request_uri or expires_in is None:
            missing = []
            if not request_uri:
                missing.append("request_uri")
            if expires_in is None:
                missing.append("expires_in")
            error_msg = (
                f"PAR response missing required fields per RFC 9126 "
                f"Section 2.2: {', '.join(missing)}"
            )
            logger.error(error_msg)
            return PushedAuthorizationResponse(
                is_successful=False, error=error_msg
            )
        logger.info("Pushed authorization request successful")
        return PushedAuthorizationResponse(
            is_successful=True,
            request_uri=request_uri,
            expires_in=expires_in,
        )

    error_msg = (
        f"Pushed authorization request failed with status code: "
        f"{response.status_code}. Response Content: {response.content}"
    )
    return PushedAuthorizationResponse(is_successful=False, error=error_msg)


__all__ = [
    "handle_par_error",
    "log_par_request",
    "prepare_par_request_data",
    "process_par_response",
]
