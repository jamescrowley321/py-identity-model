from dataclasses import dataclass
from urllib.parse import urlparse

import requests

from .exceptions import ConfigurationException, DiscoveryException
from .logging_config import logger
from .logging_utils import redact_url


def _validate_issuer(issuer: str) -> None:
    """Validate issuer format according to OpenID Connect Discovery 1.0 Section 3"""
    if not issuer:
        raise ConfigurationException("Issuer parameter is required")

    parsed = urlparse(issuer)
    if parsed.scheme != "https":
        raise ConfigurationException("Issuer must use HTTPS scheme")

    if parsed.query or parsed.fragment:
        raise ConfigurationException(
            "Issuer must not contain query or fragment components",
        )

    if not parsed.netloc:
        raise ConfigurationException("Issuer must be a valid URL with host")


def _validate_https_url(url: str, parameter_name: str) -> None:
    """Validate that a URL is a proper HTTPS URL"""
    if not url:
        return  # Optional parameters can be None/empty

    parsed = urlparse(url)
    if parsed.scheme not in ["https", "http"]:  # Allow http for development
        raise ConfigurationException(
            f"{parameter_name} must be a valid HTTP/HTTPS URL",
        )

    if not parsed.netloc:
        raise ConfigurationException(
            f"{parameter_name} must be an absolute URL with host",
        )


def _validate_required_parameters(response_data: dict) -> None:
    """Validate required parameters per OpenID Connect Discovery 1.0 Section 3"""
    required_params = [
        "issuer",
        "response_types_supported",
        "subject_types_supported",
        "id_token_signing_alg_values_supported",
    ]

    missing_params = [
        param
        for param in required_params
        if param not in response_data or response_data[param] is None
    ]

    if missing_params:
        raise DiscoveryException(
            f"Missing required parameters: {', '.join(missing_params)}",
        )


def _validate_parameter_values(response_data: dict) -> None:
    """Validate parameter values according to OpenID Connect specifications"""
    # Validate subject_types_supported values
    if response_data.get("subject_types_supported"):
        valid_subject_types = ["public", "pairwise"]
        for subject_type in response_data["subject_types_supported"]:
            if subject_type not in valid_subject_types:
                raise DiscoveryException(
                    f"Invalid subject type: {subject_type}. Must be 'public' or 'pairwise'",
                )

    # Validate response_types_supported values
    if response_data.get("response_types_supported"):
        valid_response_types = [
            "code",
            "id_token",
            "token",
            "code id_token",
            "code token",
            "id_token token",
            "code id_token token",
        ]
        for response_type in response_data["response_types_supported"]:
            if response_type not in valid_response_types:
                # Allow custom response types that contain valid components
                components = response_type.split()
                valid_components = ["code", "id_token", "token"]
                if not all(comp in valid_components for comp in components):
                    raise DiscoveryException(
                        f"Invalid response type: {response_type}",
                    )


@dataclass
class DiscoveryDocumentRequest:
    address: str


@dataclass
class DiscoveryDocumentResponse:
    is_successful: bool
    # Core OpenID Connect endpoints
    issuer: str | None = None
    jwks_uri: str | None = None
    authorization_endpoint: str | None = None
    token_endpoint: str | None = None

    # Required properties from OpenID Connect Discovery 1.0 specification
    response_types_supported: list[str] | None = None
    subject_types_supported: list[str] | None = None
    id_token_signing_alg_values_supported: list[str] | None = None

    # Common optional properties
    userinfo_endpoint: str | None = None
    registration_endpoint: str | None = None
    scopes_supported: list[str] | None = None
    response_modes_supported: list[str] | None = None
    grant_types_supported: list[str] | None = None
    acr_values_supported: list[str] | None = None

    # Cryptographic algorithm support
    id_token_encryption_alg_values_supported: list[str] | None = None
    id_token_encryption_enc_values_supported: list[str] | None = None
    userinfo_signing_alg_values_supported: list[str] | None = None
    userinfo_encryption_alg_values_supported: list[str] | None = None
    userinfo_encryption_enc_values_supported: list[str] | None = None
    request_object_signing_alg_values_supported: list[str] | None = None
    request_object_encryption_alg_values_supported: list[str] | None = None
    request_object_encryption_enc_values_supported: list[str] | None = None

    # Token endpoint authentication
    token_endpoint_auth_methods_supported: list[str] | None = None
    token_endpoint_auth_signing_alg_values_supported: list[str] | None = None

    # Display and UI
    display_values_supported: list[str] | None = None
    claim_types_supported: list[str] | None = None
    claims_supported: list[str] | None = None
    claims_locales_supported: list[str] | None = None
    ui_locales_supported: list[str] | None = None

    # Feature support flags
    claims_parameter_supported: bool | None = None
    request_parameter_supported: bool | None = None
    request_uri_parameter_supported: bool | None = None
    require_request_uri_registration: bool | None = None

    # Documentation and policy
    service_documentation: str | None = None
    op_policy_uri: str | None = None
    op_tos_uri: str | None = None

    # Internal properties
    error: str | None = None


def get_discovery_document(
    disco_doc_req: DiscoveryDocumentRequest,
) -> DiscoveryDocumentResponse:
    logger.info(
        f"Fetching discovery document from {redact_url(disco_doc_req.address)}",
    )
    try:
        response = requests.get(disco_doc_req.address, timeout=30)
        logger.debug(f"Discovery request status code: {response.status_code}")

        if not response.ok:
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
            _validate_required_parameters(response_json)
        except DiscoveryException as e:
            logger.error(f"Missing required parameters: {e!s}")
            return DiscoveryDocumentResponse(
                is_successful=False,
                error=f"Missing required parameters: {e!s}",
            )

        # Validate issuer format
        try:
            _validate_issuer(response_json.get("issuer", ""))
        except ConfigurationException as e:
            logger.error(f"Invalid issuer: {e!s}")
            return DiscoveryDocumentResponse(
                is_successful=False,
                error=f"Invalid issuer: {e!s}",
            )

        # Validate parameter values
        try:
            _validate_parameter_values(response_json)
        except DiscoveryException as e:
            logger.error(f"Invalid parameter values: {e!s}")
            return DiscoveryDocumentResponse(
                is_successful=False,
                error=f"Invalid parameter values: {e!s}",
            )

        # Validate endpoint URLs
        try:
            _validate_https_url(response_json.get("jwks_uri"), "jwks_uri")
            _validate_https_url(
                response_json.get("authorization_endpoint"),
                "authorization_endpoint",
            )
            _validate_https_url(
                response_json.get("token_endpoint"),
                "token_endpoint",
            )
            _validate_https_url(
                response_json.get("userinfo_endpoint"),
                "userinfo_endpoint",
            )
            _validate_https_url(
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

    except requests.exceptions.RequestException as e:
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
