"""
Discovery document fetching (asynchronous implementation).

This module provides asynchronous HTTP layer for fetching OpenID Connect discovery documents.
"""

import httpx

from ..core.discovery_logic import (
    log_discovery_request,
    process_discovery_response,
)
from ..core.error_handlers import handle_discovery_error
from ..core.models import DiscoveryDocumentRequest, DiscoveryDocumentResponse
from ..http_client import get_async_http_client, retry_with_backoff_async


@retry_with_backoff_async()
async def _fetch_discovery_document(
    client: httpx.AsyncClient, url: str
) -> httpx.Response:
    """
    Fetch discovery document with retry logic.

    Automatically retries on 429 (rate limiting) and 5xx errors with
    exponential backoff. Configuration is read from environment variables.
    """
    return await client.get(url)


async def get_discovery_document(
    disco_doc_req: DiscoveryDocumentRequest,
) -> DiscoveryDocumentResponse:
    """
    Fetch discovery document from the specified address (async).

    Args:
        disco_doc_req: Discovery document request configuration

    Returns:
        DiscoveryDocumentResponse: Discovery document response
    """
    log_discovery_request(disco_doc_req)
    try:
        client = get_async_http_client()
        response = await _fetch_discovery_document(
            client, disco_doc_req.address
        )
        return process_discovery_response(response)
    except Exception as e:
        return handle_discovery_error(e)


__all__ = [
    "DiscoveryDocumentRequest",
    "DiscoveryDocumentResponse",
    "get_discovery_document",
]
