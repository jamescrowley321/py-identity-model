"""Synchronous implementations of py-identity-model."""

from ..core.authorize_response import (
    AuthorizeCallbackResponse,
    parse_authorize_callback_response,
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
from .userinfo import UserInfoRequest, UserInfoResponse, get_userinfo


__all__ = [
    # Authorize Callback
    "AuthorizeCallbackResponse",
    "AuthorizeCallbackValidationResult",
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
    "StateValidationResult",
    # Token Validation
    "TokenValidationConfig",
    # UserInfo
    "UserInfoRequest",
    "UserInfoResponse",
    "get_discovery_document",
    "get_jwks",
    "get_userinfo",
    "jwks_from_dict",
    "parse_authorize_callback_response",
    "request_client_credentials_token",
    "validate_authorize_callback_state",
    "validate_token",
]
