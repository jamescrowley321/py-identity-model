"""
Token validation (asynchronous implementation).

This module provides asynchronous token validation using discovery and JWKS.
"""

import inspect

from async_lru import alru_cache

from ..core.jwt_helpers import decode_and_validate_jwt
from ..core.models import (
    DiscoveryDocumentRequest,
    DiscoveryDocumentResponse,
    JwksRequest,
    JwksResponse,
    TokenValidationConfig,
)
from ..core.parsers import get_public_key_from_jwk
from ..core.validators import validate_token_config
from ..exceptions import ConfigurationException, TokenValidationException
from ..logging_config import logger
from ..logging_utils import redact_token
from .discovery import get_discovery_document
from .jwks import get_jwks


# ============================================================================
# Caching functions (async-specific with alru_cache)
# ============================================================================


@alru_cache
async def _get_disco_response(
    disco_doc_address: str,
) -> DiscoveryDocumentResponse:
    """
    Cached async discovery document fetching.

    Cache can be cleared using _get_disco_response.cache_clear() if needed.
    """
    return await get_discovery_document(
        DiscoveryDocumentRequest(address=disco_doc_address),
    )


@alru_cache
async def _get_jwks_response(jwks_uri: str) -> JwksResponse:
    """
    Cached async JWKS fetching.

    Cache can be cleared using _get_jwks_response.cache_clear() if needed.
    """
    return await get_jwks(JwksRequest(address=jwks_uri))


# ============================================================================
# Token Validation
# ============================================================================


async def validate_token(
    jwt: str,
    token_validation_config: TokenValidationConfig,
    disco_doc_address: str | None = None,
) -> dict:
    """
    Validate a JWT token (async).

    Args:
        jwt: The JWT token to validate
        token_validation_config: Token validation configuration
        disco_doc_address: Discovery document address (required if perform_disco=True)

    Returns:
        dict: Decoded token claims

    Raises:
        TokenValidationException: If token validation fails
        ConfigurationException: If configuration is invalid
    """
    logger.info(f"Starting token validation, token: {redact_token(jwt)}")
    logger.debug(
        f"Validation config - perform_disco: {token_validation_config.perform_disco}, "
        f"audience: {token_validation_config.audience}",
    )

    validate_token_config(token_validation_config)

    if token_validation_config.perform_disco:
        disco_doc_response = await _get_disco_response(disco_doc_address)

        if not disco_doc_response.is_successful:
            error_msg = (
                disco_doc_response.error or "Discovery document request failed"
            )
            logger.error(f"Discovery failed: {error_msg}")
            raise TokenValidationException(error_msg)

        jwks_response = await _get_jwks_response(disco_doc_response.jwks_uri)
        if not jwks_response.is_successful:
            error_msg = jwks_response.error or "JWKS request failed"
            logger.error(f"JWKS fetch failed: {error_msg}")
            raise TokenValidationException(error_msg)

        if not jwks_response.keys:
            error_msg = "No keys available in JWKS response"
            logger.error(error_msg)
            raise TokenValidationException(error_msg)

        token_validation_config.key = get_public_key_from_jwk(
            jwt,
            jwks_response.keys,
        ).as_dict()
        token_validation_config.algorithms = [
            token_validation_config.key["alg"],
        ]

        decoded_token = decode_and_validate_jwt(
            jwt=jwt,
            key=token_validation_config.key,
            algorithms=token_validation_config.algorithms,
            audience=token_validation_config.audience,
            issuer=disco_doc_response.issuer,
            options=token_validation_config.options,
        )
    else:
        if not token_validation_config.key:
            raise ConfigurationException(
                "TokenValidationConfig.key is required",
            )
        if not token_validation_config.algorithms:
            raise ConfigurationException(
                "TokenValidationConfig.algorithms is required",
            )

        decoded_token = decode_and_validate_jwt(
            jwt=jwt,
            key=token_validation_config.key,
            algorithms=token_validation_config.algorithms,
            audience=token_validation_config.audience,
            issuer=token_validation_config.issuer,
            options=token_validation_config.options,
        )

    if token_validation_config.claims_validator:
        try:
            # Check if the claims_validator is async
            if inspect.iscoroutinefunction(
                token_validation_config.claims_validator
            ):
                await token_validation_config.claims_validator(decoded_token)
            else:
                token_validation_config.claims_validator(decoded_token)
        except Exception as e:
            logger.error(f"Claims validation failed: {e!s}")
            raise TokenValidationException(
                f"Claims validation failed: {e!s}",
                token_part="payload",
                details={"error": str(e)},
            ) from e

    logger.info(
        f"Token validation successful for subject: {decoded_token.get('sub', 'unknown')}",
    )
    logger.debug(f"Decoded token claims: {list(decoded_token.keys())}")
    return decoded_token


__all__ = ["TokenValidationConfig", "validate_token"]
