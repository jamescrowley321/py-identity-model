"""
JWKS fetching (asynchronous implementation).

This module provides asynchronous HTTP layer for fetching JSON Web Key Sets.
"""

import httpx

from ..core.error_handlers import handle_jwks_error
from ..core.jwks_logic import log_jwks_request, process_jwks_response
from ..core.models import (
    JsonWebAlgorithmsKeyTypes,
    JsonWebKey,
    JsonWebKeyParameterNames,
    JwksRequest,
    JwksResponse,
)
from ..core.parsers import jwks_from_dict
from .http_client import get_async_http_client, retry_with_backoff_async


@retry_with_backoff_async()
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
    log_jwks_request(jwks_request)
    try:
        client = get_async_http_client()
        response = await _fetch_jwks(client, jwks_request.address)
        return process_jwks_response(response)
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
