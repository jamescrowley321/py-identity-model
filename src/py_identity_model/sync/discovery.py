"""
Discovery document fetching (synchronous implementation).

This module provides synchronous HTTP layer for fetching OpenID Connect discovery documents.
"""

import httpx

from ..core.error_handlers import handle_discovery_error
from ..core.models import DiscoveryDocumentRequest, DiscoveryDocumentResponse
from ..core.response_processors import (
    build_discovery_response,
    validate_and_parse_discovery_response,
)
from ..http_client import get_http_client, retry_on_rate_limit
from ..logging_config import logger
from ..logging_utils import redact_url


@retry_on_rate_limit()
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
) -> DiscoveryDocumentResponse:
    """
    Fetch discovery document from the specified address.

    Args:
        disco_doc_req: Discovery document request configuration

    Returns:
        DiscoveryDocumentResponse: Discovery document response
    """
    logger.info(
        f"Fetching discovery document from {redact_url(disco_doc_req.address)}",
    )
    try:
        client = get_http_client()
        response = _fetch_discovery_document(client, disco_doc_req.address)
        logger.debug(f"Discovery request status code: {response.status_code}")

        if not response.is_success:
            error_msg = (
                f"Discovery document request failed with status code: "
                f"{response.status_code}. Response Content: {response.content}"
            )
            logger.error(error_msg)
            return DiscoveryDocumentResponse(
                is_successful=False,
                error=error_msg,
            )

        # Validate and parse response using shared logic
        response_json = validate_and_parse_discovery_response(response)

        logger.info(
            f"Discovery document fetched successfully, issuer: {response_json.get('issuer')}",
        )
        logger.debug(
            f"JWKS URI: {response_json.get('jwks_uri')}, "
            f"Token endpoint: {response_json.get('token_endpoint')}",
        )

        # Build response using shared logic
        return build_discovery_response(response_json)

    except Exception as e:
        return handle_discovery_error(e)


__all__ = [
    "DiscoveryDocumentRequest",
    "DiscoveryDocumentResponse",
    "get_discovery_document",
]
