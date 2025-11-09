"""
JWKS fetching (asynchronous implementation).

This module provides asynchronous HTTP layer for fetching JSON Web Key Sets.
"""

import httpx

from ..core.error_handlers import handle_jwks_error
from ..core.models import (
    JsonWebAlgorithmsKeyTypes,
    JsonWebKey,
    JsonWebKeyParameterNames,
    JwksRequest,
    JwksResponse,
)
from ..core.parsers import jwks_from_dict
from ..core.response_processors import parse_jwks_response
from ..http_client import get_async_http_client, retry_on_rate_limit_async
from ..logging_config import logger
from ..logging_utils import redact_url


@retry_on_rate_limit_async()
async def _fetch_jwks(client: httpx.AsyncClient, url: str) -> httpx.Response:
    """
    Fetch JWKS with retry logic.

    Automatically retries on 429 (rate limiting) and 5xx errors with
    exponential backoff. Configuration is read from environment variables.
    """
    return await client.get(url)


async def get_jwks(jwks_request: JwksRequest) -> JwksResponse:
    """
    Fetch JWKS from the specified address (async).

    Args:
        jwks_request: JWKS request configuration

    Returns:
        JwksResponse: JWKS response with keys
    """
    logger.info(f"Fetching JWKS from {redact_url(jwks_request.address)}")
    try:
        client = get_async_http_client()
        response = await _fetch_jwks(client, jwks_request.address)
        logger.debug(f"JWKS request status code: {response.status_code}")

        # Parse response using shared logic
        jwks_response = parse_jwks_response(response)

        if jwks_response.is_successful and jwks_response.keys:
            logger.info(
                f"JWKS fetched successfully, found {len(jwks_response.keys)} keys"
            )
            logger.debug(
                f"Key IDs: {[k.kid for k in jwks_response.keys if k.kid is not None]}",
            )

        return jwks_response

    except Exception as e:
        return handle_jwks_error(e)


__all__ = [
    "JsonWebAlgorithmsKeyTypes",
    "JsonWebKey",
    "JsonWebKeyParameterNames",
    "JwksRequest",
    "JwksResponse",
    "get_jwks",
    "jwks_from_dict",
]
