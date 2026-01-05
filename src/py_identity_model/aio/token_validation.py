"""
Token validation (asynchronous implementation).

This module provides asynchronous token validation using discovery and JWKS.
"""

from async_lru import alru_cache

from ..core.models import (
    DiscoveryDocumentRequest,
    DiscoveryDocumentResponse,
    JwksRequest,
    JwksResponse,
    TokenValidationConfig,
)
from ..core.parsers import extract_kid_from_jwt
from ..core.token_validation_logic import (
    decode_with_config,
    log_validation_start,
    log_validation_success,
    validate_async_claims,
    validate_config_for_manual_validation,
    validate_disco_response,
    validate_jwks_response,
)
from ..core.validators import validate_token_config
from ..exceptions import TokenValidationException
from .discovery import get_discovery_document
from .jwks import get_jwks


# ============================================================================
# Caching functions (async-specific with alru_cache)
# ============================================================================


@alru_cache(maxsize=128)
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


@alru_cache(maxsize=128)
async def _get_jwks_response(jwks_uri: str) -> JwksResponse:
    """
    Cached async JWKS fetching.

    Cache can be cleared using _get_jwks_response.cache_clear() if needed.
    """
    return await get_jwks(JwksRequest(address=jwks_uri))


@alru_cache(maxsize=128)
async def _get_public_key_by_kid(
    kid: str | None, jwks_uri: str
) -> tuple[dict, str]:
    """Cached public key extraction from JWKS by key ID.

    Args:
        kid: The key ID from the JWT header
        jwks_uri: The JWKS URI to fetch keys from

    Returns:
        tuple: (public_key_dict, algorithm)

    Note:
        This cache uses the kid (key ID) instead of the full JWT for efficient
        caching. Multiple JWTs signed with the same key will share a cache entry.
    """
    jwks_response = await _get_jwks_response(jwks_uri)
    if not jwks_response.keys:
        raise TokenValidationException("No keys available in JWKS response")

    # Find key by kid
    filtered_keys = [k for k in jwks_response.keys if k.kid == kid]
    if not filtered_keys:
        available_kids = [k.kid for k in jwks_response.keys if k.kid]
        raise TokenValidationException(
            f"No matching kid found: {kid}",
            token_part="header",
            details={"kid": kid, "available_kids": available_kids},
        )

    public_key = filtered_keys[0]
    alg = public_key.alg if public_key.alg else "RS256"
    return public_key.as_dict(), alg


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
    log_validation_start(jwt, token_validation_config)
    validate_token_config(token_validation_config)

    if token_validation_config.perform_disco:
        disco_doc_response = await _get_disco_response(disco_doc_address)
        validate_disco_response(disco_doc_response)

        jwks_response = await _get_jwks_response(disco_doc_response.jwks_uri)
        validate_jwks_response(jwks_response)

        # Extract kid from JWT and use cached public key lookup for performance
        kid = extract_kid_from_jwt(jwt)
        key_dict, alg = await _get_public_key_by_kid(
            kid, disco_doc_response.jwks_uri
        )

        # Use local variables instead of mutating the config object
        decoded_token = decode_with_config(
            jwt,
            TokenValidationConfig(
                perform_disco=token_validation_config.perform_disco,
                key=key_dict,
                audience=token_validation_config.audience,
                algorithms=[alg],
                issuer=token_validation_config.issuer,
                subject=token_validation_config.subject,
                options=token_validation_config.options,
                claims_validator=token_validation_config.claims_validator,
            ),
            disco_doc_response.issuer,
        )
    else:
        validate_config_for_manual_validation(token_validation_config)
        decoded_token = decode_with_config(jwt, token_validation_config)

    # Use shared async claims validation logic
    await validate_async_claims(decoded_token, token_validation_config)

    log_validation_success(decoded_token)
    return decoded_token


__all__ = ["TokenValidationConfig", "validate_token"]
