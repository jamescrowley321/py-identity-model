"""
Validation functions for py-identity-model.

This module contains all validation logic used by both sync and async implementations.
"""

from urllib.parse import urlparse

from ..exceptions import ConfigurationException, DiscoveryException
from .models import TokenValidationConfig


# ============================================================================
# Discovery Document Validation
# ============================================================================


def validate_issuer(issuer: str) -> None:
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


def validate_https_url(url: str, parameter_name: str) -> None:
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


def validate_required_parameters(response_data: dict) -> None:
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


def validate_parameter_values(response_data: dict) -> None:
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


# ============================================================================
# Token Validation Configuration
# ============================================================================


def validate_token_config(
    token_validation_config: TokenValidationConfig,
) -> None:
    """
    Validate token validation configuration.

    Args:
        token_validation_config: Configuration to validate

    Raises:
        ConfigurationException: If configuration is invalid
    """
    if token_validation_config.perform_disco:
        return

    if (
        not token_validation_config.key
        and not token_validation_config.algorithms
    ):
        raise ConfigurationException(
            "TokenValidationConfig.key and TokenValidationConfig.algorithms are required if perform_disco is False",
        )


__all__ = [
    "validate_https_url",
    "validate_issuer",
    "validate_parameter_values",
    "validate_required_parameters",
    "validate_token_config",
]
