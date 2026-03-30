"""
Discovery document fetching (synchronous implementation).

This module provides synchronous HTTP layer for fetching OpenID Connect discovery documents.
"""

import httpx

from ..core.discovery_logic import (
    log_discovery_request,
    process_discovery_response,
)
from ..core.error_handlers import handle_discovery_error
from ..core.models import DiscoveryDocumentRequest, DiscoveryDocumentResponse
from .http_client import get_http_client, retry_with_backoff
from .managed_client import HTTPClient


@retry_with_backoff()
def _fetch_discovery_document(
    client: httpx.Client, url: str
) -> httpx.Response:
    """
    Fetch discovery document with retry logic.

    Automatically retries on 429 (rate limiting) and 5xx errors with
    exponential backoff. Configuration is read from environment variables.
    """
    return client.get(url)


def get_discovery_document(
    disco_doc_req: DiscoveryDocumentRequest,
    http_client: HTTPClient | None = None,
) -> DiscoveryDocumentResponse:
    """
    Fetch discovery document from the specified address.

    Args:
        disco_doc_req: Discovery document request configuration
        http_client: Optional managed HTTP client.  When ``None``, uses the
            thread-local default.

    Returns:
        DiscoveryDocumentResponse: Discovery document response
    """
    log_discovery_request(disco_doc_req)
    try:
        client = http_client.client if http_client else get_http_client()
        response = _fetch_discovery_document(client, disco_doc_req.address)
        result = process_discovery_response(
            response, require_https=disco_doc_req.require_https
        )
        # Explicitly close the response to ensure the connection is released
        response.close()
        return result
    except Exception as e:
        return handle_discovery_error(e)


__all__ = [
    "DiscoveryDocumentRequest",
    "DiscoveryDocumentResponse",
    "get_discovery_document",
]
