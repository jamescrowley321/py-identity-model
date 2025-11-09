"""Synchronous implementations of py-identity-model."""

from .discovery import (
    DiscoveryDocumentRequest,
    DiscoveryDocumentResponse,
    get_discovery_document,
)
from .jwks import (
    JsonWebAlgorithmsKeyTypes,
    JsonWebKey,
    JsonWebKeyParameterNames,
    JwksRequest,
    JwksResponse,
    get_jwks,
    jwks_from_dict,
)
from .token_client import (
    ClientCredentialsTokenRequest,
    ClientCredentialsTokenResponse,
    request_client_credentials_token,
)
from .token_validation import TokenValidationConfig, validate_token


__all__ = [
    # Token Client
    "ClientCredentialsTokenRequest",
    "ClientCredentialsTokenResponse",
    # Discovery
    "DiscoveryDocumentRequest",
    "DiscoveryDocumentResponse",
    # JWKS
    "JsonWebAlgorithmsKeyTypes",
    "JsonWebKey",
    "JsonWebKeyParameterNames",
    "JwksRequest",
    "JwksResponse",
    # Token Validation
    "TokenValidationConfig",
    "get_discovery_document",
    "get_jwks",
    "jwks_from_dict",
    "request_client_credentials_token",
    "validate_token",
]
