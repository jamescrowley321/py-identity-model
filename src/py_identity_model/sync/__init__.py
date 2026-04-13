"""Synchronous implementations of py-identity-model."""

from ..core.authorize_response import (
    AuthorizeCallbackResponse,
    parse_authorize_callback_response,
)
from ..core.authorize_url import build_authorization_url
from ..core.discovery_policy import (
    DiscoveryEndpoint,
    DiscoveryPolicy,
    parse_discovery_url,
)
from ..core.dpop import (
    DPoPKey,
    build_dpop_headers,
    compute_ath,
    create_dpop_proof,
    generate_dpop_key,
)
from ..core.fapi import (
    FAPI2_ALLOWED_AUTH_METHODS,
    FAPI2_ALLOWED_SIGNING_ALGORITHMS,
    FAPI2_REQUIRED_PKCE_METHOD,
    FAPI2_REQUIRED_RESPONSE_TYPE,
    FAPIValidationResult,
    validate_fapi_authorization_request,
    validate_fapi_client_config,
    validate_fapi_discovery,
)
from ..core.jar import build_jar_authorization_url, create_request_object
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
from .device_auth import (
    DeviceAuthorizationRequest,
    DeviceAuthorizationResponse,
    DeviceTokenRequest,
    DeviceTokenResponse,
    poll_device_token,
    request_device_authorization,
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
from .par import (
    PushedAuthorizationRequest,
    PushedAuthorizationResponse,
    push_authorization_request,
)
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
from .token_exchange import (
    TokenExchangeRequest,
    TokenExchangeResponse,
    exchange_token,
)
from .token_validation import (
    TokenValidationConfig,
    clear_discovery_cache,
    clear_jwks_cache,
    validate_token,
)
from .userinfo import UserInfoRequest, UserInfoResponse, get_userinfo


__all__ = [
    # FAPI 2.0
    "FAPI2_ALLOWED_AUTH_METHODS",
    "FAPI2_ALLOWED_SIGNING_ALGORITHMS",
    "FAPI2_REQUIRED_PKCE_METHOD",
    "FAPI2_REQUIRED_RESPONSE_TYPE",
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
    # DPoP
    "DPoPKey",
    # Device Authorization Grant
    "DeviceAuthorizationRequest",
    "DeviceAuthorizationResponse",
    "DeviceTokenRequest",
    "DeviceTokenResponse",
    # Discovery
    "DiscoveryDocumentRequest",
    "DiscoveryDocumentResponse",
    # Discovery Policy
    "DiscoveryEndpoint",
    "DiscoveryPolicy",
    "FAPIValidationResult",
    # HTTP Client
    "HTTPClient",
    # JWKS
    "JsonWebAlgorithmsKeyTypes",
    "JsonWebKey",
    "JsonWebKeyParameterNames",
    "JwksRequest",
    "JwksResponse",
    # PAR
    "PushedAuthorizationRequest",
    "PushedAuthorizationResponse",
    # Refresh Token
    "RefreshTokenRequest",
    "RefreshTokenResponse",
    "StateValidationResult",
    # Token Exchange
    "TokenExchangeRequest",
    "TokenExchangeResponse",
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
    "build_dpop_headers",
    "build_jar_authorization_url",
    "clear_discovery_cache",
    "clear_jwks_cache",
    "compute_ath",
    "create_dpop_proof",
    "create_request_object",
    "exchange_token",
    "generate_code_challenge",
    "generate_code_verifier",
    "generate_dpop_key",
    "generate_pkce_pair",
    "get_discovery_document",
    "get_jwks",
    "get_userinfo",
    "introspect_token",
    "jwks_from_dict",
    "parse_authorize_callback_response",
    "parse_discovery_url",
    "poll_device_token",
    "push_authorization_request",
    "refresh_token",
    "request_authorization_code_token",
    "request_client_credentials_token",
    "request_device_authorization",
    "revoke_token",
    "validate_authorize_callback_state",
    "validate_fapi_authorization_request",
    "validate_fapi_client_config",
    "validate_fapi_discovery",
    "validate_token",
]
