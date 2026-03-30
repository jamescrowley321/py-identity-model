"""Synchronous implementations of py-identity-model."""

from ..core.authorize_response import (
    AuthorizeCallbackResponse,
    parse_authorize_callback_response,
)
from ..core.authorize_url import build_authorization_url
from ..core.models import BaseRequest, BaseResponse
from ..core.pkce import (
    generate_code_challenge,
    generate_code_verifier,
    generate_pkce_pair,
)
from ..core.state_validation import (
    AuthorizeCallbackValidationResult,
    StateValidationResult,
    validate_authorize_callback_state,
)
from .discovery import (
    DiscoveryDocumentRequest,
    DiscoveryDocumentResponse,
    get_discovery_document,
)
from .introspection import (
    TokenIntrospectionRequest,
    TokenIntrospectionResponse,
    introspect_token,
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
from .managed_client import HTTPClient
from .revocation import (
    TokenRevocationRequest,
    TokenRevocationResponse,
    revoke_token,
)
from .token_client import (
    AuthorizationCodeTokenRequest,
    AuthorizationCodeTokenResponse,
    ClientCredentialsTokenRequest,
    ClientCredentialsTokenResponse,
    RefreshTokenRequest,
    RefreshTokenResponse,
    refresh_token,
    request_authorization_code_token,
    request_client_credentials_token,
)
from .token_validation import TokenValidationConfig, validate_token
from .userinfo import UserInfoRequest, UserInfoResponse, get_userinfo


__all__ = [
    # Auth Code + PKCE
    "AuthorizationCodeTokenRequest",
    "AuthorizationCodeTokenResponse",
    # Authorize Callback
    "AuthorizeCallbackResponse",
    "AuthorizeCallbackValidationResult",
    # Base Classes
    "BaseRequest",
    "BaseResponse",
    # Token Client
    "ClientCredentialsTokenRequest",
    "ClientCredentialsTokenResponse",
    # Discovery
    "DiscoveryDocumentRequest",
    "DiscoveryDocumentResponse",
    # HTTP Client
    "HTTPClient",
    # JWKS
    "JsonWebAlgorithmsKeyTypes",
    "JsonWebKey",
    "JsonWebKeyParameterNames",
    "JwksRequest",
    "JwksResponse",
    # Refresh Token
    "RefreshTokenRequest",
    "RefreshTokenResponse",
    "StateValidationResult",
    # Token Introspection
    "TokenIntrospectionRequest",
    "TokenIntrospectionResponse",
    # Token Revocation
    "TokenRevocationRequest",
    "TokenRevocationResponse",
    # Token Validation
    "TokenValidationConfig",
    # UserInfo
    "UserInfoRequest",
    "UserInfoResponse",
    "build_authorization_url",
    "generate_code_challenge",
    "generate_code_verifier",
    "generate_pkce_pair",
    "get_discovery_document",
    "get_jwks",
    "get_userinfo",
    "introspect_token",
    "jwks_from_dict",
    "parse_authorize_callback_response",
    "refresh_token",
    "request_authorization_code_token",
    "request_client_credentials_token",
    "revoke_token",
    "validate_authorize_callback_state",
    "validate_token",
]
