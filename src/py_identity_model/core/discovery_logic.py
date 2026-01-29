"""
Shared business logic for discovery document operations.

This module contains the common processing logic used by both sync and async
discovery implementations, reducing code duplication.
"""

import httpx

from ..logging_config import logger
from ..logging_utils import redact_url
from .error_handlers import handle_discovery_error
from .models import DiscoveryDocumentRequest, DiscoveryDocumentResponse
from .response_processors import (
    build_discovery_response,
    validate_and_parse_discovery_response,
)


def log_discovery_request(disco_doc_req: DiscoveryDocumentRequest) -> None:
    """Log discovery document request."""
    logger.info(
        f"Fetching discovery document from {redact_url(disco_doc_req.address)}",
    )


def log_discovery_status(status_code: int) -> None:
    """Log discovery response status code."""
    logger.debug(f"Discovery request status code: {status_code}")


def handle_unsuccessful_response(
    response: httpx.Response,
) -> DiscoveryDocumentResponse:
    """Handle unsuccessful discovery response."""
    error_msg = (
        f"Discovery document request failed with status code: "
        f"{response.status_code}. Response Content: {response.content}"
    )
    logger.error(error_msg)
    return DiscoveryDocumentResponse(
        is_successful=False,
        error=error_msg,
    )


def process_successful_response(
    response: httpx.Response,
) -> DiscoveryDocumentResponse:
    """Process successful discovery response."""
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


def process_discovery_response(
    response: httpx.Response,
) -> DiscoveryDocumentResponse:
    """
    Process discovery document response.

    Args:
        response: HTTP response from discovery endpoint

    Returns:
        DiscoveryDocumentResponse with parsed data or error
    """
    log_discovery_status(response.status_code)

    if not response.is_success:
        return handle_unsuccessful_response(response)

    try:
        return process_successful_response(response)
    except Exception as e:
        return handle_discovery_error(e)
