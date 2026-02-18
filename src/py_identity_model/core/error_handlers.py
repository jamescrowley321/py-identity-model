"""
Shared error handling logic for HTTP requests.

This module provides common error handling patterns used by both
sync and async implementations.
"""

import httpx

from ..exceptions import ConfigurationException, DiscoveryException
from ..logging_config import logger
from .models import (
    ClientCredentialsTokenResponse,
    DiscoveryDocumentResponse,
    JwksResponse,
    UserInfoResponse,
)


def handle_discovery_error(e: Exception) -> DiscoveryDocumentResponse:
    """
    Handle errors during discovery document requests.

    Args:
        e: Exception that occurred

    Returns:
        DiscoveryDocumentResponse: Error response
    """
    if isinstance(e, ConfigurationException):
        # Wrap configuration exceptions for backwards compatibility
        if "issuer" in str(e).lower():
            error_msg = f"Invalid issuer: {e!s}"
        elif "url" in str(e).lower():
            error_msg = f"Invalid endpoint URL: {e!s}"
        else:
            error_msg = str(e)
        logger.error(error_msg)
        return DiscoveryDocumentResponse(
            is_successful=False,
            error=error_msg,
        )

    if isinstance(e, DiscoveryException):
        # Wrap discovery exceptions for backwards compatibility
        if "parameter" in str(e).lower() and "subject" not in str(e).lower():
            error_msg = f"Missing required parameters: {e!s}"
        elif "subject" in str(e).lower() or "response_type" in str(e).lower():
            error_msg = f"Invalid parameter values: {e!s}"
        else:
            error_msg = str(e)
        logger.error(error_msg)
        return DiscoveryDocumentResponse(
            is_successful=False,
            error=error_msg,
        )

    if isinstance(e, httpx.RequestError):
        error_msg = f"Network error during discovery document request: {e!s}"
        logger.error(error_msg, exc_info=True)
        return DiscoveryDocumentResponse(
            is_successful=False,
            error=error_msg,
        )

    error_msg = f"Unexpected error during discovery document request: {e!s}"
    logger.error(error_msg, exc_info=True)
    return DiscoveryDocumentResponse(
        is_successful=False,
        error=error_msg,
    )


def handle_jwks_error(e: Exception) -> JwksResponse:
    """
    Handle errors during JWKS requests.

    Args:
        e: Exception that occurred

    Returns:
        JwksResponse: Error response
    """
    if isinstance(e, httpx.RequestError):
        error_msg = f"Network error during JWKS request: {e!s}"
        logger.error(error_msg, exc_info=True)
        return JwksResponse(
            is_successful=False,
            error=error_msg,
        )

    error_msg = f"Unhandled exception during JWKS request: {e!s}"
    logger.error(error_msg, exc_info=True)
    return JwksResponse(
        is_successful=False,
        error=error_msg,
    )


def handle_token_error(e: Exception) -> ClientCredentialsTokenResponse:
    """
    Handle errors during token requests.

    Args:
        e: Exception that occurred

    Returns:
        ClientCredentialsTokenResponse: Error response
    """
    if isinstance(e, httpx.RequestError):
        error_msg = f"Network error during token request: {e!s}"
        logger.error(error_msg, exc_info=True)
        return ClientCredentialsTokenResponse(
            is_successful=False,
            error=error_msg,
        )

    error_msg = f"Unexpected error during token request: {e!s}"
    logger.error(error_msg, exc_info=True)
    return ClientCredentialsTokenResponse(
        is_successful=False,
        error=error_msg,
    )


def handle_userinfo_error(e: Exception) -> UserInfoResponse:
    """
    Handle errors during UserInfo requests.

    Args:
        e: Exception that occurred

    Returns:
        UserInfoResponse: Error response
    """
    if isinstance(e, httpx.RequestError):
        error_msg = f"Network error during UserInfo request: {e!s}"
        logger.error(error_msg, exc_info=True)
        return UserInfoResponse(
            is_successful=False,
            error=error_msg,
        )

    error_msg = f"Unexpected error during UserInfo request: {e!s}"
    logger.error(error_msg, exc_info=True)
    return UserInfoResponse(
        is_successful=False,
        error=error_msg,
    )


__all__ = [
    "handle_discovery_error",
    "handle_jwks_error",
    "handle_token_error",
    "handle_userinfo_error",
]
