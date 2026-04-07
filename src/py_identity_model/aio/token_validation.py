"""
Token validation (asynchronous implementation).

This module provides asynchronous token validation using discovery and JWKS.
"""

import asyncio
import time

from async_lru import alru_cache

from ..core.jwks_cache import (
    JwksCacheEntry,
    get_jwks_cache_ttl,
    is_cache_expired,
)
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
    validate_jwks_uri,
)
from ..core.validators import validate_token_config
from ..exceptions import ConfigurationException, SignatureVerificationException
from ..logging_config import logger
from .discovery import get_discovery_document
from .jwks import get_jwks
from .managed_client import AsyncHTTPClient


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


# ============================================================================
# TTL-aware JWKS cache (replaces @alru_cache for JWKS)
# ============================================================================

_jwks_cache: dict[str, JwksCacheEntry] = {}
_jwks_cache_lock = asyncio.Lock()


async def _get_cached_jwks(jwks_uri: str) -> JwksResponse:
    """Return cached JWKS response if fresh, otherwise fetch and cache.

    Args:
        jwks_uri: The JWKS endpoint URI.

    Returns:
        The JWKS response (possibly cached).
    """
    ttl = get_jwks_cache_ttl()
    async with _jwks_cache_lock:
        entry = _jwks_cache.get(jwks_uri)
        if entry is not None and not is_cache_expired(entry, ttl):
            return entry.response

    # Fetch outside the lock to avoid blocking other coroutines
    response = await get_jwks(JwksRequest(address=jwks_uri))

    async with _jwks_cache_lock:
        _jwks_cache[jwks_uri] = JwksCacheEntry(response=response, cached_at=time.time())
    return response


async def _refresh_jwks(jwks_uri: str) -> JwksResponse:
    """Force re-fetch JWKS and update cache.

    Used when signature verification fails with cached keys,
    indicating a possible key rotation.

    Args:
        jwks_uri: The JWKS endpoint URI.

    Returns:
        The freshly fetched JWKS response.
    """
    logger.info("Forcing JWKS refresh for %s (possible key rotation)", jwks_uri)
    response = await get_jwks(JwksRequest(address=jwks_uri))
    async with _jwks_cache_lock:
        _jwks_cache[jwks_uri] = JwksCacheEntry(response=response, cached_at=time.time())
    return response


def clear_jwks_cache() -> None:
    """Clear the JWKS cache. Useful for testing."""
    _jwks_cache.clear()


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
                DiscoveryDocumentRequest(address=disco_doc_address),
                http_client=http_client,
            )
            validate_disco_response(disco_doc_response)
            jwks_uri = validate_jwks_uri(disco_doc_response)

            jwks_response = await get_jwks(
                JwksRequest(address=jwks_uri),
                http_client=http_client,
            )
            validate_jwks_response(jwks_response)

            kid = extract_kid_from_jwt(jwt)
            key_dict, alg = find_key_by_kid(kid, jwks_response.keys or [])
        else:
            # Cached path with TTL
            disco_doc_response = await _get_disco_response(disco_doc_address)
            validate_disco_response(disco_doc_response)
            jwks_uri = validate_jwks_uri(disco_doc_response)

            jwks_response = await _get_cached_jwks(jwks_uri)
            validate_jwks_response(jwks_response)

            kid = extract_kid_from_jwt(jwt)
            key_dict, alg = find_key_by_kid(kid, jwks_response.keys or [])

        # Build validation config with discovered key
        resolved_config = TokenValidationConfig(
            perform_disco=token_validation_config.perform_disco,
            key=key_dict,
            audience=token_validation_config.audience,
            algorithms=[alg],
            issuer=token_validation_config.issuer,
            subject=token_validation_config.subject,
            options=token_validation_config.options,
            claims_validator=token_validation_config.claims_validator,
            leeway=token_validation_config.leeway,
        )

        try:
            decoded_token = decode_with_config(
                jwt, resolved_config, disco_doc_response.issuer
            )
        except SignatureVerificationException:
            if http_client is not None:
                # DI path — no cache to refresh, re-raise
                raise
            # Cached path — force JWKS refresh and retry once (key rotation)
            logger.warning(
                "Signature verification failed with cached JWKS; "
                "retrying with refreshed keys"
            )
            jwks_response = await _refresh_jwks(jwks_uri)
            validate_jwks_response(jwks_response)
            key_dict, alg = find_key_by_kid(kid, jwks_response.keys or [])

            resolved_config = TokenValidationConfig(
                perform_disco=token_validation_config.perform_disco,
                key=key_dict,
                audience=token_validation_config.audience,
                algorithms=[alg],
                issuer=token_validation_config.issuer,
                subject=token_validation_config.subject,
                options=token_validation_config.options,
                claims_validator=token_validation_config.claims_validator,
                leeway=token_validation_config.leeway,
            )
            decoded_token = decode_with_config(
                jwt, resolved_config, disco_doc_response.issuer
            )
    else:
        validate_config_for_manual_validation(token_validation_config)
        decoded_token = decode_with_config(jwt, token_validation_config)

    # Use shared async claims validation logic
    await validate_async_claims(decoded_token, token_validation_config)

    log_validation_success(decoded_token)
    return decoded_token


__all__ = ["TokenValidationConfig", "clear_jwks_cache", "validate_token"]
