"""
Token validation (synchronous implementation).

This module provides synchronous token validation using discovery and JWKS.
"""

from functools import lru_cache

from ..core.models import (
    DiscoveryDocumentRequest,
    DiscoveryDocumentResponse,
    JwksRequest,
    JwksResponse,
    TokenValidationConfig,
)
from ..core.parsers import get_public_key_from_jwk
from ..core.token_validation_logic import (
    decode_with_config,
    log_validation_start,
    log_validation_success,
    validate_claims,
    validate_config_for_manual_validation,
    validate_disco_response,
    validate_jwks_response,
)
from ..core.validators import validate_token_config
from ..exceptions import TokenValidationException
from .discovery import get_discovery_document
from .jwks import get_jwks


# ============================================================================
# Caching functions (sync-specific with lru_cache)
# ============================================================================


@lru_cache
def _get_disco_response(disco_doc_address: str) -> DiscoveryDocumentResponse:
    """
    Cached discovery document fetching.

    Note: httpx creates new connections for each request. For better performance
    in applications making many discovery requests, consider using httpx.Client
    with connection pooling. However, with this LRU cache, discovery documents
    are only fetched once per address, making the connection overhead minimal.
    """
    return get_discovery_document(
        DiscoveryDocumentRequest(address=disco_doc_address),
    )


@lru_cache
def _get_jwks_response(jwks_uri: str) -> JwksResponse:
    """Cached JWKS fetching."""
    return get_jwks(JwksRequest(address=jwks_uri))


@lru_cache(maxsize=128)
def _get_public_key(jwt: str, jwks_uri: str) -> tuple[dict, str]:
    """Cached public key extraction from JWKS.

    Args:
        jwt: The JWT token (used to extract kid from header)
        jwks_uri: The JWKS URI to fetch keys from

    Returns:
        tuple: (public_key_dict, algorithm)

    Note:
        This cache uses the JWT itself as part of the key. In practice, the same
        JWT is validated repeatedly in benchmarks. In production, different JWTs
        with the same kid will have different cache entries, which is acceptable
        given the maxsize limit.

        TODO: Consider implementing HTTP-aware caching that respects Cache-Control
        and Expires headers for disco/JWKS responses.
    """
    jwks_response = _get_jwks_response(jwks_uri)
    if not jwks_response.keys:
        raise TokenValidationException("No keys available in JWKS response")
    public_key = get_public_key_from_jwk(jwt, jwks_response.keys)
    alg = public_key.alg if public_key.alg else "RS256"
    return public_key.as_dict(), alg


# ============================================================================
# Token Validation
# ============================================================================


def validate_token(
    jwt: str,
    token_validation_config: TokenValidationConfig,
    disco_doc_address: str | None = None,
) -> dict:
    """
    Validate a JWT token.

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
        disco_doc_response = _get_disco_response(disco_doc_address)
        validate_disco_response(disco_doc_response)

        jwks_response = _get_jwks_response(disco_doc_response.jwks_uri)
        validate_jwks_response(jwks_response)

        # Use cached public key lookup for performance
        key_dict, alg = _get_public_key(jwt, disco_doc_response.jwks_uri)
        token_validation_config.key = key_dict
        token_validation_config.algorithms = [alg]

        decoded_token = decode_with_config(
            jwt, token_validation_config, disco_doc_response.issuer
        )
    else:
        validate_config_for_manual_validation(token_validation_config)
        decoded_token = decode_with_config(jwt, token_validation_config)

    validate_claims(decoded_token, token_validation_config)
    log_validation_success(decoded_token)
    return decoded_token


__all__ = ["TokenValidationConfig", "validate_token"]
