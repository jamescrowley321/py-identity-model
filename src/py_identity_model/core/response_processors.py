"""
Shared response processing logic for HTTP responses.

This module provides common response validation and parsing logic used by both
sync and async implementations.
"""

import httpx

from ..exceptions import DiscoveryException
from .models import (
    ClientCredentialsTokenResponse,
    DiscoveryDocumentResponse,
    JwksResponse,
)
from .parsers import jwks_from_dict
from .validators import (
    validate_https_url,
    validate_issuer,
    validate_parameter_values,
    validate_required_parameters,
)


def validate_and_parse_discovery_response(
    response: httpx.Response,
) -> dict:
    """
    Validate and parse discovery document HTTP response.

    Args:
        response: HTTP response from discovery endpoint

    Returns:
        dict: Parsed discovery document JSON

    Raises:
        DiscoveryException: If response is invalid
    """
    # Check content type
    if "application/json" not in response.headers.get("Content-Type", ""):
        raise DiscoveryException(
            f"Invalid content type. Expected application/json, got: "
            f"{response.headers.get('Content-Type', 'unknown')}"
        )

    # Parse JSON
    try:
        response_json = response.json()
    except ValueError as e:
        raise DiscoveryException(f"Invalid JSON response: {e!s}") from e

    # Validate required parameters
    validate_required_parameters(response_json)

    # Validate issuer format
    validate_issuer(response_json.get("issuer", ""))

    # Validate parameter values
    validate_parameter_values(response_json)

    # Validate endpoint URLs
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

    return response_json


def build_discovery_response(
    response_json: dict,
) -> DiscoveryDocumentResponse:
    """
    Build DiscoveryDocumentResponse from validated JSON.

    Args:
        response_json: Validated discovery document JSON

    Returns:
        DiscoveryDocumentResponse: Success response with discovery data
    """
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


def parse_jwks_response(response: httpx.Response) -> JwksResponse:
    """
    Parse JWKS HTTP response.

    Args:
        response: HTTP response from JWKS endpoint

    Returns:
        JwksResponse: Parsed JWKS response with keys
    """
    if response.is_success:
        response_json = response.json()
        keys = [jwks_from_dict(key) for key in response_json["keys"]]
        return JwksResponse(is_successful=True, keys=keys)

    error_msg = (
        f"JSON web keys request failed with status code: "
        f"{response.status_code}. Response Content: {response.content}"
    )
    return JwksResponse(
        is_successful=False,
        error=error_msg,
    )


def parse_token_response(
    response: httpx.Response,
) -> ClientCredentialsTokenResponse:
    """
    Parse token HTTP response.

    Args:
        response: HTTP response from token endpoint

    Returns:
        ClientCredentialsTokenResponse: Parsed token response
    """
    if response.is_success:
        response_json = response.json()
        return ClientCredentialsTokenResponse(
            is_successful=True,
            token=response_json,
        )

    error_msg = (
        f"Token generation request failed with status code: "
        f"{response.status_code}. Response Content: {response.content}"
    )
    return ClientCredentialsTokenResponse(
        is_successful=False,
        error=error_msg,
    )


__all__ = [
    "build_discovery_response",
    "parse_jwks_response",
    "parse_token_response",
    "validate_and_parse_discovery_response",
]
