"""
Core token validation business logic (sync/async agnostic).

This module contains the shared validation logic used by both sync and async
implementations to reduce code duplication.
"""

from ..core.jwt_helpers import decode_and_validate_jwt
from ..core.models import (
    DiscoveryDocumentResponse,
    JwksResponse,
    TokenValidationConfig,
)
from ..exceptions import ConfigurationException, TokenValidationException
from ..logging_config import logger


def validate_disco_response(
    disco_doc_response: DiscoveryDocumentResponse,
) -> None:
    """
    Validate discovery document response.

    Args:
        disco_doc_response: Discovery document response to validate

    Raises:
        TokenValidationException: If discovery response is not successful
    """
    if not disco_doc_response.is_successful:
        error_msg = (
            disco_doc_response.error or "Discovery document request failed"
        )
        logger.error(f"Discovery failed: {error_msg}")
        raise TokenValidationException(error_msg)


def validate_jwks_response(jwks_response: JwksResponse) -> None:
    """
    Validate JWKS response.

    Args:
        jwks_response: JWKS response to validate

    Raises:
        TokenValidationException: If JWKS response is not successful or has no keys
    """
    if not jwks_response.is_successful:
        error_msg = jwks_response.error or "JWKS request failed"
        logger.error(f"JWKS fetch failed: {error_msg}")
        raise TokenValidationException(error_msg)

    if not jwks_response.keys:
        error_msg = "No keys available in JWKS response"
        logger.error(error_msg)
        raise TokenValidationException(error_msg)


def validate_config_for_manual_validation(
    token_validation_config: TokenValidationConfig,
) -> None:
    """
    Validate token configuration for manual validation (non-discovery mode).

    Args:
        token_validation_config: Token validation configuration

    Raises:
        ConfigurationException: If required configuration is missing
    """
    if not token_validation_config.key:
        raise ConfigurationException(
            "TokenValidationConfig.key is required",
        )
    if not token_validation_config.algorithms:
        raise ConfigurationException(
            "TokenValidationConfig.algorithms is required",
        )


def decode_with_config(
    jwt: str,
    token_validation_config: TokenValidationConfig,
    issuer: str | None = None,
) -> dict:
    """
    Decode and validate JWT using the token validation configuration.

    Args:
        jwt: The JWT token to decode
        token_validation_config: Token validation configuration with key and algorithms set
        issuer: Optional issuer override (from discovery document)

    Returns:
        dict: Decoded token claims

    Raises:
        TokenValidationException: If token validation fails
        ConfigurationException: If key or algorithms are missing
    """
    if (
        not token_validation_config.key
        or not token_validation_config.algorithms
    ):
        raise ConfigurationException(
            "Token validation configuration must have key and algorithms set"
        )

    return decode_and_validate_jwt(
        jwt=jwt,
        key=token_validation_config.key,
        algorithms=token_validation_config.algorithms,
        audience=token_validation_config.audience,
        issuer=issuer or token_validation_config.issuer,
        options=token_validation_config.options,
    )


def validate_claims(
    decoded_token: dict,
    token_validation_config: TokenValidationConfig,
) -> None:
    """
    Validate claims using custom validator if provided.

    Args:
        decoded_token: Decoded token claims
        token_validation_config: Token validation configuration

    Raises:
        TokenValidationException: If claims validation fails
    """
    if token_validation_config.claims_validator:
        try:
            token_validation_config.claims_validator(decoded_token)
        except Exception as e:
            logger.error(f"Claims validation failed: {e!s}")
            raise TokenValidationException(
                f"Claims validation failed: {e!s}",
                token_part="payload",
                details={"error": str(e)},
            ) from e


def log_validation_start(
    jwt: str, token_validation_config: TokenValidationConfig
) -> None:
    """
    Log validation start information.

    Args:
        jwt: The JWT token (will be redacted in logs)
        token_validation_config: Token validation configuration
    """
    from ..logging_utils import redact_token

    logger.info(f"Starting token validation, token: {redact_token(jwt)}")
    logger.debug(
        f"Validation config - perform_disco: {token_validation_config.perform_disco}, "
        f"audience: {token_validation_config.audience}",
    )


def log_validation_success(decoded_token: dict) -> None:
    """
    Log successful validation.

    Args:
        decoded_token: The decoded token claims
    """
    logger.info(
        f"Token validation successful for subject: {decoded_token.get('sub', 'unknown')}",
    )
    logger.debug(f"Decoded token claims: {list(decoded_token.keys())}")


__all__ = [
    "decode_with_config",
    "log_validation_start",
    "log_validation_success",
    "validate_claims",
    "validate_config_for_manual_validation",
    "validate_disco_response",
    "validate_jwks_response",
]
