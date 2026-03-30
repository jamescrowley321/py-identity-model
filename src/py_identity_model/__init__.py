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
    AuthorizationCodeTokenRequest,
    AuthorizationCodeTokenResponse,
    AuthorizeCallbackResponse,
    AuthorizeCallbackValidationResult,
    BaseRequest,
    BaseResponse,
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
    TokenIntrospectionRequest,
    TokenIntrospectionResponse,
    TokenValidationConfig,
    UserInfoRequest,
    UserInfoResponse,
    build_authorization_url,
    generate_code_challenge,
    generate_code_verifier,
    generate_pkce_pair,
    get_discovery_document,
    get_jwks,
    get_userinfo,
    introspect_token,
    jwks_from_dict,
    parse_authorize_callback_response,
    request_authorization_code_token,
    request_client_credentials_token,
    validate_authorize_callback_state,
    validate_token,
)


__all__ = [
    # Auth Code + PKCE
    "AuthorizationCodeTokenRequest",
    "AuthorizationCodeTokenResponse",
    # Authorize Callback
    "AuthorizeCallbackException",
    "AuthorizeCallbackResponse",
    "AuthorizeCallbackValidationResult",
    # Base Classes
    "BaseRequest",
    "BaseResponse",
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
    # Token Introspection
    "TokenIntrospectionRequest",
    "TokenIntrospectionResponse",
    "TokenRequestException",
    "TokenValidationConfig",
    "TokenValidationException",
    "UserInfoException",
    "UserInfoRequest",
    "UserInfoResponse",
    "ValidationException",
    "build_authorization_url",
    "generate_code_challenge",
    "generate_code_verifier",
    "generate_pkce_pair",
    # Sync API (default)
    "get_discovery_document",
    "get_jwks",
    "get_userinfo",
    "introspect_token",
    "jwks_from_dict",
    "parse_authorize_callback_response",
    "request_authorization_code_token",
    "request_client_credentials_token",
    "to_principal",
    "validate_authorize_callback_state",
    "validate_token",
]
