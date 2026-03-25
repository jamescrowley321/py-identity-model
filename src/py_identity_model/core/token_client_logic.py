"""
Shared business logic for token client operations.

This module contains the common processing logic used by both sync and async
token client implementations, reducing code duplication.
"""

import httpx

from ..logging_config import logger
from ..logging_utils import redact_url
from .error_handlers import (
    handle_auth_code_token_error,
    handle_refresh_token_error,
    handle_token_error,
)
from .models import (
    AuthorizationCodeTokenRequest,
    AuthorizationCodeTokenResponse,
    ClientCredentialsTokenRequest,
    ClientCredentialsTokenResponse,
    RefreshTokenRequest,
    RefreshTokenResponse,
)
from .response_processors import (
    parse_auth_code_token_response,
    parse_refresh_token_response,
    parse_token_response,
)


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


# ============================================================================
# Authorization Code Token Exchange
# ============================================================================


def log_auth_code_token_request(
    request: AuthorizationCodeTokenRequest,
) -> None:
    """Log authorization code token exchange request."""
    logger.info(
        f"Exchanging authorization code at {redact_url(request.address)}",
    )
    logger.debug(f"Client ID: {request.client_id}")


def prepare_auth_code_token_request_data(
    request: AuthorizationCodeTokenRequest,
) -> tuple[dict, dict, tuple[str, str] | None]:
    """Prepare request data, headers, and optional auth for auth code exchange.

    Returns:
        ``(data, headers, auth)`` where *auth* is ``None`` for public clients.
    """
    params: dict[str, str] = {
        "grant_type": "authorization_code",
        "code": request.code,
        "redirect_uri": request.redirect_uri,
    }
    if request.code_verifier is not None:
        params["code_verifier"] = request.code_verifier
    if request.scope is not None:
        params["scope"] = request.scope

    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    auth: tuple[str, str] | None = None
    if request.client_secret is not None:
        # RFC 6749 §2.3.1: use Basic auth for confidential clients;
        # client_id is carried in the auth header, not the body.
        auth = (request.client_id, request.client_secret)
    else:
        # Public client: include client_id in the request body
        params["client_id"] = request.client_id

    return params, headers, auth


def process_auth_code_token_response(
    response: httpx.Response,
) -> AuthorizationCodeTokenResponse:
    """Process authorization code token exchange response."""
    log_token_status(response.status_code)

    try:
        token_response = parse_auth_code_token_response(response)
        if token_response.is_successful and token_response.token:
            logger.info("Authorization code token exchange successful")
        return token_response
    except Exception as e:
        return handle_auth_code_token_error(e)


# ============================================================================
# Refresh Token Grant
# ============================================================================


def log_refresh_token_request(request: RefreshTokenRequest) -> None:
    """Log refresh token request."""
    logger.info(f"Refreshing token at {redact_url(request.address)}")
    logger.debug(f"Client ID: {request.client_id}")


def prepare_refresh_token_request_data(
    request: RefreshTokenRequest,
) -> tuple[dict, dict, tuple[str, str] | None]:
    """Prepare request data, headers, and optional auth for refresh grant."""
    params: dict[str, str] = {
        "grant_type": "refresh_token",
        "refresh_token": request.refresh_token,
        "client_id": request.client_id,
    }
    if request.scope is not None:
        params["scope"] = request.scope

    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    auth: tuple[str, str] | None = None
    if request.client_secret is not None:
        auth = (request.client_id, request.client_secret)

    return params, headers, auth


def process_refresh_token_response(
    response: httpx.Response,
) -> RefreshTokenResponse:
    """Process refresh token grant response."""
    log_token_status(response.status_code)

    try:
        token_response = parse_refresh_token_response(response)
        if token_response.is_successful and token_response.token:
            logger.info("Token refresh successful")
        return token_response
    except Exception as e:
        return handle_refresh_token_error(e)
