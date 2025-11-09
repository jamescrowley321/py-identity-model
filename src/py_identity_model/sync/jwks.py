"""
JWKS fetching (synchronous implementation).

This module provides synchronous HTTP layer for fetching JSON Web Key Sets.
"""

import httpx

from ..core.models import (
    JsonWebAlgorithmsKeyTypes,
    JsonWebKey,
    JsonWebKeyParameterNames,
    JwksRequest,
    JwksResponse,
)
from ..core.parsers import jwks_from_dict
from ..logging_config import logger
from ..logging_utils import redact_url
from ..ssl_config import get_ssl_verify


def get_jwks(jwks_request: JwksRequest) -> JwksResponse:
    """
    Fetch JWKS from the specified address.

    Args:
        jwks_request: JWKS request configuration

    Returns:
        JwksResponse: JWKS response with keys
    """
    logger.info(f"Fetching JWKS from {redact_url(jwks_request.address)}")
    try:
        response = httpx.get(
            jwks_request.address, timeout=30.0, verify=get_ssl_verify()
        )
        logger.debug(f"JWKS request status code: {response.status_code}")

        if response.is_success:
            response_json = response.json()
            keys = [jwks_from_dict(key) for key in response_json["keys"]]
            logger.info(f"JWKS fetched successfully, found {len(keys)} keys")
            logger.debug(
                f"Key IDs: {[k.kid for k in keys if k.kid is not None]}",
            )
            return JwksResponse(is_successful=True, keys=keys)
        error_msg = (
            f"JSON web keys request failed with status code: "
            f"{response.status_code}. Response Content: {response.content}"
        )
        logger.error(error_msg)
        return JwksResponse(
            is_successful=False,
            error=error_msg,
        )
    except httpx.RequestError as e:
        error_msg = f"Network error during JWKS request: {e!s}"
        logger.error(error_msg, exc_info=True)
        return JwksResponse(
            is_successful=False,
            error=error_msg,
        )
    except Exception as e:
        error_msg = f"Unhandled exception during JWKS request: {e!s}"
        logger.error(error_msg, exc_info=True)
        return JwksResponse(
            is_successful=False,
            error=error_msg,
        )


__all__ = [
    "JsonWebAlgorithmsKeyTypes",
    "JsonWebKey",
    "JsonWebKeyParameterNames",
    "JwksRequest",
    "JwksResponse",
    "get_jwks",
    "jwks_from_dict",
]
