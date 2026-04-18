"""
Asynchronous token validation with TTL-based JWKS and discovery caching.

This module provides asynchronous token validation using discovery and JWKS,
with automatic cache expiry and forced JWKS refresh on key rotation.
"""

import asyncio
import time

from ..core.discovery_policy import DiscoveryPolicy
from ..core.jwks_cache import (
    DiscoCacheEntry,
    JwksCacheEntry,
    is_cache_expired,
    resolve_disco_ttl,
    resolve_ttl,
)
from ..core.models import (
    DiscoveryDocumentRequest,
    DiscoveryDocumentResponse,
    JwksRequest,
    JwksResponse,
    TokenValidationConfig,
)
from ..core.parsers import (
    extract_jwt_header_fields,
    find_key_by_kid,
)
from ..core.token_validation_logic import (
    build_resolved_config,
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
# Discovery TTL cache
# ============================================================================

# Discovery TTL cache — keyed by (address, require_https) to prevent policy bypass
_disco_cache: dict[tuple[str, bool], DiscoCacheEntry] = {}
_disco_cache_lock = asyncio.Lock()


async def _get_disco_response(
    disco_doc_address: str | None,
    require_https: bool = True,
) -> DiscoveryDocumentResponse:
    """Cached async discovery document fetching with TTL."""
    if disco_doc_address is None:
        raise ConfigurationException(
            "disco_doc_address is required when perform_disco is True"
        )

    cache_key = (disco_doc_address, require_https)
    async with _disco_cache_lock:
        entry = _disco_cache.get(cache_key)
        if entry is not None and not is_cache_expired(entry):
            return entry.response

        # Fetch under lock to prevent cache stampede (single-flight refresh)
        policy = DiscoveryPolicy(require_https=require_https)
        response = await get_discovery_document(
            DiscoveryDocumentRequest(address=disco_doc_address, policy=policy),
        )
        ttl = resolve_disco_ttl(response.cache_control)
        _disco_cache[cache_key] = DiscoCacheEntry(
            response=response, cached_at=time.time(), ttl=ttl
        )
        return response


def clear_discovery_cache() -> None:
    """Clear the discovery cache."""
    _disco_cache.clear()


# ============================================================================
# TTL-aware JWKS cache (replaces @alru_cache for JWKS)
# ============================================================================

_jwks_cache: dict[str, JwksCacheEntry] = {}
_jwks_cache_lock = asyncio.Lock()


async def _get_cached_jwks(jwks_uri: str) -> JwksResponse:
    """Return cached JWKS response if fresh, otherwise fetch and cache."""
    async with _jwks_cache_lock:
        entry = _jwks_cache.get(jwks_uri)
        if entry is not None and not is_cache_expired(entry):
            return entry.response

        # Fetch under lock to prevent cache stampede (single-flight refresh)
        response = await get_jwks(JwksRequest(address=jwks_uri))
        ttl = resolve_ttl(response.cache_control)
        _jwks_cache[jwks_uri] = JwksCacheEntry(
            response=response, cached_at=time.time(), ttl=ttl
        )
        return response


async def _refresh_jwks(jwks_uri: str) -> JwksResponse:
    """Force re-fetch JWKS and update cache (key rotation)."""
    request_time = time.time()
    async with _jwks_cache_lock:
        # If another coroutine already refreshed while we waited on the lock,
        # return the fresh entry to avoid redundant sequential fetches
        entry = _jwks_cache.get(jwks_uri)
        if entry is not None and entry.cached_at >= request_time:
            return entry.response

        logger.info("Forcing JWKS refresh for %s (possible key rotation)", jwks_uri)
        response = await get_jwks(JwksRequest(address=jwks_uri))
        ttl = resolve_ttl(response.cache_control)
        _jwks_cache[jwks_uri] = JwksCacheEntry(
            response=response, cached_at=time.time(), ttl=ttl
        )
        return response


def clear_jwks_cache() -> None:
    """Clear the JWKS cache. Useful for testing."""
    _jwks_cache.clear()


# ============================================================================
# Token validation
# ============================================================================


async def _discover_and_resolve_key(
    jwt: str,
    disco_doc_address: str | None,
    http_client: AsyncHTTPClient | None,
    require_https: bool = True,
) -> tuple[dict, str, DiscoveryDocumentResponse, bool]:
    """Fetch discovery + JWKS and resolve the signing key.

    Returns (key_dict, alg, disco_response, is_cached_path).
    """
    if http_client is not None:
        if disco_doc_address is None:
            raise ConfigurationException(
                "disco_doc_address is required when perform_disco is True"
            )
        policy = DiscoveryPolicy(require_https=require_https)
        disco_doc_response = await get_discovery_document(
            DiscoveryDocumentRequest(address=disco_doc_address, policy=policy),
            http_client=http_client,
        )
        validate_disco_response(disco_doc_response)
        jwks_uri = validate_jwks_uri(disco_doc_response)
        jwks_response = await get_jwks(
            JwksRequest(address=jwks_uri), http_client=http_client
        )
        validate_jwks_response(jwks_response)
        kid, jwt_alg = extract_jwt_header_fields(jwt)
        key_dict, alg = find_key_by_kid(kid, jwks_response.keys or [], jwt_alg=jwt_alg)
        return key_dict, alg, disco_doc_response, False

    # Cached path with TTL
    disco_doc_response = await _get_disco_response(disco_doc_address, require_https)
    validate_disco_response(disco_doc_response)
    jwks_uri = validate_jwks_uri(disco_doc_response)
    jwks_response = await _get_cached_jwks(jwks_uri)
    validate_jwks_response(jwks_response)
    kid, jwt_alg = extract_jwt_header_fields(jwt)
    key_dict, alg = find_key_by_kid(kid, jwks_response.keys or [], jwt_alg=jwt_alg)
    return key_dict, alg, disco_doc_response, True


async def _retry_with_refreshed_jwks(
    jwt: str,
    token_validation_config: TokenValidationConfig,
    disco_doc_response: DiscoveryDocumentResponse,
    http_client: AsyncHTTPClient | None = None,
) -> dict:
    """Re-fetch JWKS and retry decode once (key rotation recovery)."""
    logger.warning("Signature verification failed; retrying with refreshed keys")
    jwks_uri = validate_jwks_uri(disco_doc_response)
    if http_client is not None:
        jwks_response = await get_jwks(
            JwksRequest(address=jwks_uri), http_client=http_client
        )
    else:
        jwks_response = await _refresh_jwks(jwks_uri)
    validate_jwks_response(jwks_response)
    kid, jwt_alg = extract_jwt_header_fields(jwt)
    key_dict, alg = find_key_by_kid(kid, jwks_response.keys or [], jwt_alg=jwt_alg)
    resolved_config = build_resolved_config(token_validation_config, key_dict, alg)
    return decode_with_config(jwt, resolved_config, disco_doc_response.issuer)


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
        key_dict, alg, disco_doc_response, _is_cached = await _discover_and_resolve_key(
            jwt, disco_doc_address, http_client, token_validation_config.require_https
        )
        resolved_config = build_resolved_config(token_validation_config, key_dict, alg)

        try:
            decoded_token = decode_with_config(
                jwt, resolved_config, disco_doc_response.issuer
            )
        except SignatureVerificationException:
            decoded_token = await _retry_with_refreshed_jwks(
                jwt, token_validation_config, disco_doc_response, http_client
            )
    else:
        validate_config_for_manual_validation(token_validation_config)
        decoded_token = decode_with_config(jwt, token_validation_config)

    await validate_async_claims(decoded_token, token_validation_config)
    log_validation_success(decoded_token)
    return decoded_token


__all__ = [
    "TokenValidationConfig",
    "clear_discovery_cache",
    "clear_jwks_cache",
    "validate_token",
]
