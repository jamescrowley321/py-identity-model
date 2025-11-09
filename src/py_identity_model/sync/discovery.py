"""
Discovery document fetching (synchronous implementation).

This module provides synchronous HTTP layer for fetching OpenID Connect discovery documents.
"""

import httpx

from ..core.models import DiscoveryDocumentRequest, DiscoveryDocumentResponse
from ..core.validators import (
    validate_https_url,
    validate_issuer,
    validate_parameter_values,
    validate_required_parameters,
)
from ..exceptions import ConfigurationException, DiscoveryException
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

        if "application/json" not in response.headers.get("Content-Type", ""):
            error_msg = (
                f"Invalid content type. Expected application/json, got: "
                f"{response.headers.get('Content-Type', 'unknown')}"
            )
            logger.error(error_msg)
            return DiscoveryDocumentResponse(
                is_successful=False,
                error=error_msg,
            )

        try:
            response_json = response.json()
        except ValueError as e:
            error_msg = f"Invalid JSON response: {e!s}"
            logger.error(error_msg, exc_info=True)
            return DiscoveryDocumentResponse(
                is_successful=False,
                error=error_msg,
            )

        # Validate required parameters
        try:
            validate_required_parameters(response_json)
        except DiscoveryException as e:
            logger.error(f"Missing required parameters: {e!s}")
            return DiscoveryDocumentResponse(
                is_successful=False,
                error=f"Missing required parameters: {e!s}",
            )

        # Validate issuer format
        try:
            validate_issuer(response_json.get("issuer", ""))
        except ConfigurationException as e:
            logger.error(f"Invalid issuer: {e!s}")
            return DiscoveryDocumentResponse(
                is_successful=False,
                error=f"Invalid issuer: {e!s}",
            )

        # Validate parameter values
        try:
            validate_parameter_values(response_json)
        except DiscoveryException as e:
            logger.error(f"Invalid parameter values: {e!s}")
            return DiscoveryDocumentResponse(
                is_successful=False,
                error=f"Invalid parameter values: {e!s}",
            )

        # Validate endpoint URLs
        try:
            validate_https_url(response_json.get("jwks_uri"), "jwks_uri")
            validate_https_url(
                response_json.get("authorization_endpoint"),
                "authorization_endpoint",
            )
            validate_https_url(
                response_json.get("token_endpoint"),
                "token_endpoint",
            )
            validate_https_url(
                response_json.get("userinfo_endpoint"),
                "userinfo_endpoint",
            )
            validate_https_url(
                response_json.get("registration_endpoint"),
                "registration_endpoint",
            )
        except ConfigurationException as e:
            logger.error(f"Invalid endpoint URL: {e!s}")
            return DiscoveryDocumentResponse(
                is_successful=False,
                error=f"Invalid endpoint URL: {e!s}",
            )

        logger.info(
            f"Discovery document fetched successfully, issuer: {response_json.get('issuer')}",
        )
        logger.debug(
            f"JWKS URI: {response_json.get('jwks_uri')}, "
            f"Token endpoint: {response_json.get('token_endpoint')}",
        )

        return DiscoveryDocumentResponse(
            # Core OpenID Connect endpoints
            issuer=response_json.get("issuer"),
            jwks_uri=response_json.get("jwks_uri"),
            authorization_endpoint=response_json.get("authorization_endpoint"),
            token_endpoint=response_json.get("token_endpoint"),
            # Required properties from OpenID Connect Discovery 1.0 specification
            response_types_supported=response_json.get(
                "response_types_supported",
            ),
            subject_types_supported=response_json.get(
                "subject_types_supported",
            ),
            id_token_signing_alg_values_supported=response_json.get(
                "id_token_signing_alg_values_supported",
            ),
            # Common optional properties
            userinfo_endpoint=response_json.get("userinfo_endpoint"),
            registration_endpoint=response_json.get("registration_endpoint"),
            scopes_supported=response_json.get("scopes_supported"),
            response_modes_supported=response_json.get(
                "response_modes_supported",
            ),
            grant_types_supported=response_json.get("grant_types_supported"),
            acr_values_supported=response_json.get("acr_values_supported"),
            # Cryptographic algorithm support
            id_token_encryption_alg_values_supported=response_json.get(
                "id_token_encryption_alg_values_supported",
            ),
            id_token_encryption_enc_values_supported=response_json.get(
                "id_token_encryption_enc_values_supported",
            ),
            userinfo_signing_alg_values_supported=response_json.get(
                "userinfo_signing_alg_values_supported",
            ),
            userinfo_encryption_alg_values_supported=response_json.get(
                "userinfo_encryption_alg_values_supported",
            ),
            userinfo_encryption_enc_values_supported=response_json.get(
                "userinfo_encryption_enc_values_supported",
            ),
            request_object_signing_alg_values_supported=response_json.get(
                "request_object_signing_alg_values_supported",
            ),
            request_object_encryption_alg_values_supported=response_json.get(
                "request_object_encryption_alg_values_supported",
            ),
            request_object_encryption_enc_values_supported=response_json.get(
                "request_object_encryption_enc_values_supported",
            ),
            # Token endpoint authentication
            token_endpoint_auth_methods_supported=response_json.get(
                "token_endpoint_auth_methods_supported",
            ),
            token_endpoint_auth_signing_alg_values_supported=response_json.get(
                "token_endpoint_auth_signing_alg_values_supported",
            ),
            # Display and UI
            display_values_supported=response_json.get(
                "display_values_supported",
            ),
            claim_types_supported=response_json.get("claim_types_supported"),
            claims_supported=response_json.get("claims_supported"),
            claims_locales_supported=response_json.get(
                "claims_locales_supported",
            ),
            ui_locales_supported=response_json.get("ui_locales_supported"),
            # Feature support flags
            claims_parameter_supported=response_json.get(
                "claims_parameter_supported",
            ),
            request_parameter_supported=response_json.get(
                "request_parameter_supported",
            ),
            request_uri_parameter_supported=response_json.get(
                "request_uri_parameter_supported",
            ),
            require_request_uri_registration=response_json.get(
                "require_request_uri_registration",
            ),
            # Documentation and policy
            service_documentation=response_json.get("service_documentation"),
            op_policy_uri=response_json.get("op_policy_uri"),
            op_tos_uri=response_json.get("op_tos_uri"),
            is_successful=True,
        )

    except httpx.RequestError as e:
        error_msg = f"Network error during discovery document request: {e!s}"
        logger.error(error_msg, exc_info=True)
        return DiscoveryDocumentResponse(
            is_successful=False,
            error=error_msg,
        )
    except Exception as e:
        error_msg = (
            f"Unexpected error during discovery document request: {e!s}"
        )
        logger.error(error_msg, exc_info=True)
        return DiscoveryDocumentResponse(
            is_successful=False,
            error=error_msg,
        )


__all__ = [
    "DiscoveryDocumentRequest",
    "DiscoveryDocumentResponse",
    "get_discovery_document",
]
