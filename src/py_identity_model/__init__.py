"""py-identity-model: OAuth2.0 and OpenID Connect Client Library

Provides both synchronous and asynchronous APIs for OpenID Connect operations.
"""

# Initialize SSL compatibility for backward compatibility with requests library
from . import ssl_config  # noqa: F401

# Backward compatible sync exports (default)
from .exceptions import (
    ConfigurationException,
    DiscoveryException,
    InvalidAudienceException,
    InvalidIssuerException,
    JwksException,
    NetworkException,
    PyIdentityModelException,
    SignatureVerificationException,
    TokenExpiredException,
    TokenRequestException,
    TokenValidationException,
    ValidationException,
)

# Identity models (shared)
from .identity import Claim, ClaimsIdentity, ClaimsPrincipal, to_principal
from .sync import (
    ClientCredentialsTokenRequest,
    ClientCredentialsTokenResponse,
    DiscoveryDocumentRequest,
    DiscoveryDocumentResponse,
    JsonWebAlgorithmsKeyTypes,
    JsonWebKey,
    JsonWebKeyParameterNames,
    JwksRequest,
    JwksResponse,
    TokenValidationConfig,
    get_discovery_document,
    get_jwks,
    jwks_from_dict,
    request_client_credentials_token,
    validate_token,
)


__all__ = [
    # Identity models
    "Claim",
    "ClaimsIdentity",
    "ClaimsPrincipal",
    "ClientCredentialsTokenRequest",
    "ClientCredentialsTokenResponse",
    "ConfigurationException",
    # Request/Response models
    "DiscoveryDocumentRequest",
    "DiscoveryDocumentResponse",
    "DiscoveryException",
    "InvalidAudienceException",
    "InvalidIssuerException",
    "JsonWebAlgorithmsKeyTypes",
    "JsonWebKey",
    "JsonWebKeyParameterNames",
    "JwksException",
    "JwksRequest",
    "JwksResponse",
    "NetworkException",
    # Exceptions
    "PyIdentityModelException",
    "SignatureVerificationException",
    "TokenExpiredException",
    "TokenRequestException",
    "TokenValidationConfig",
    "TokenValidationException",
    "ValidationException",
    # Sync API (default)
    "get_discovery_document",
    "get_jwks",
    "jwks_from_dict",
    "request_client_credentials_token",
    "to_principal",
    "validate_token",
]
