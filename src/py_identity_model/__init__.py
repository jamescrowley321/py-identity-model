"""py-identity-model: OAuth2.0 and OpenID Connect Client Library

Provides both synchronous and asynchronous APIs for OpenID Connect operations.
"""

# Initialize SSL compatibility for backward compatibility with requests library
from . import ssl_config  # noqa: F401

# Backward compatible sync exports (default)
from .exceptions import (
    AuthorizeCallbackException,
    ConfigurationException,
    DiscoveryException,
    FailedResponseAccessError,
    InvalidAudienceException,
    InvalidIssuerException,
    JwksException,
    NetworkException,
    PyIdentityModelException,
    SignatureVerificationException,
    SuccessfulResponseAccessError,
    TokenExpiredException,
    TokenRequestException,
    TokenValidationException,
    UserInfoException,
    ValidationException,
)

# Identity models (shared)
from .identity import Claim, ClaimsIdentity, ClaimsPrincipal, to_principal
from .sync import (
    AuthorizeCallbackResponse,
    AuthorizeCallbackValidationResult,
    ClientCredentialsTokenRequest,
    ClientCredentialsTokenResponse,
    DiscoveryDocumentRequest,
    DiscoveryDocumentResponse,
    HTTPClient,
    JsonWebAlgorithmsKeyTypes,
    JsonWebKey,
    JsonWebKeyParameterNames,
    JwksRequest,
    JwksResponse,
    StateValidationResult,
    TokenValidationConfig,
    UserInfoRequest,
    UserInfoResponse,
    get_discovery_document,
    get_jwks,
    get_userinfo,
    jwks_from_dict,
    parse_authorize_callback_response,
    request_client_credentials_token,
    validate_authorize_callback_state,
    validate_token,
)


__all__ = [
    # Authorize Callback
    "AuthorizeCallbackException",
    "AuthorizeCallbackResponse",
    "AuthorizeCallbackValidationResult",
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
    "FailedResponseAccessError",
    # HTTP Client
    "HTTPClient",
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
    "StateValidationResult",
    "SuccessfulResponseAccessError",
    "TokenExpiredException",
    "TokenRequestException",
    "TokenValidationConfig",
    "TokenValidationException",
    "UserInfoException",
    "UserInfoRequest",
    "UserInfoResponse",
    "ValidationException",
    # Sync API (default)
    "get_discovery_document",
    "get_jwks",
    "get_userinfo",
    "jwks_from_dict",
    "parse_authorize_callback_response",
    "request_client_credentials_token",
    "to_principal",
    "validate_authorize_callback_state",
    "validate_token",
]
