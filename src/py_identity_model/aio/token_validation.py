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
from ..core.parsers import extract_kid_from_jwt, find_key_by_kid
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
from ..exceptions import ConfigurationException
from .discovery import get_discovery_document
from .jwks import get_jwks
from .managed_client import AsyncHTTPClient


# ============================================================================
# Caching functions (async-specific with alru_cache)
# ============================================================================


@alru_cache(maxsize=128)
async def _get_disco_response(
    disco_doc_address: str,
    require_https: bool = True,
) -> DiscoveryDocumentResponse:
    """
    Cached async discovery document fetching.

    Cache can be cleared using _get_disco_response.cache_clear() if needed.
    """
    return await get_discovery_document(
        DiscoveryDocumentRequest(
            address=disco_doc_address, require_https=require_https
        ),
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
    return find_key_by_kid(kid, jwks_response.keys or [])


# ============================================================================
# Token Validation
# ============================================================================


async def validate_token(
    jwt: str,
    token_validation_config: TokenValidationConfig,
    disco_doc_address: str | None = None,
    http_client: AsyncHTTPClient | None = None,
) -> dict:
    """
    Validate a JWT token (async).

    Args:
        jwt: The JWT token to validate
        token_validation_config: Token validation configuration
        disco_doc_address: Discovery document address (required if perform_disco=True)
        http_client: Optional managed HTTP client.  When ``None``, uses the
            module-level singleton with response caching.  When provided,
            caching is bypassed and the injected client is used directly.

    Returns:
        dict: Decoded token claims

    Raises:
        TokenValidationException: If token validation fails
        ConfigurationException: If configuration is invalid
    """
    log_validation_start(jwt, token_validation_config)
    validate_token_config(token_validation_config)

    if token_validation_config.perform_disco:
        if http_client is not None:
            # Bypass cache — use injected client directly
            if disco_doc_address is None:
                raise ConfigurationException(
                    "disco_doc_address is required when perform_disco is True"
                )
            disco_doc_response = await get_discovery_document(
                DiscoveryDocumentRequest(
                    address=disco_doc_address,
                    require_https=token_validation_config.require_https,
                ),
                http_client=http_client,
            )
            validate_disco_response(disco_doc_response)

            if disco_doc_response.jwks_uri is None:
                raise ConfigurationException(
                    "Discovery document missing jwks_uri"
                )
            jwks_response = await get_jwks(
                JwksRequest(address=disco_doc_response.jwks_uri),
                http_client=http_client,
            )
            validate_jwks_response(jwks_response)

            kid = extract_kid_from_jwt(jwt)
            key_dict, alg = find_key_by_kid(kid, jwks_response.keys or [])
        else:
            # Cached path (existing behavior)
            disco_doc_response = await _get_disco_response(
                disco_doc_address, token_validation_config.require_https
            )
            validate_disco_response(disco_doc_response)

            if disco_doc_response.jwks_uri is None:
                raise ConfigurationException(
                    "Discovery document missing jwks_uri"
                )
            jwks_response = await _get_jwks_response(
                disco_doc_response.jwks_uri
            )
            validate_jwks_response(jwks_response)

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
                leeway=token_validation_config.leeway,
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
