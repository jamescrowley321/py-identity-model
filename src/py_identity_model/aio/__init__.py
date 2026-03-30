"""Asynchronous implementations of py-identity-model.

This module provides async/await versions of all client methods
for non-blocking I/O operations.

Example:
    ```python
    from py_identity_model import DiscoveryDocumentRequest
    from py_identity_model.aio import get_discovery_document


    async def main():
        request = DiscoveryDocumentRequest(
            address="https://example.com/.well-known/openid-configuration"
        )
        response = await get_discovery_document(request)
        if response.is_successful:
            print(f"Issuer: {response.issuer}")
    ```
"""

# Initialize SSL compatibility for backward compatibility with requests library
from .. import ssl_config  # noqa: F401
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
from .jwks import (
    JsonWebAlgorithmsKeyTypes,
    JsonWebKey,
    JsonWebKeyParameterNames,
    JwksRequest,
    JwksResponse,
    get_jwks,
    jwks_from_dict,
)
from .managed_client import AsyncHTTPClient
from .token_client import (
    AuthorizationCodeTokenRequest,
    AuthorizationCodeTokenResponse,
    ClientCredentialsTokenRequest,
    ClientCredentialsTokenResponse,
    request_authorization_code_token,
    request_client_credentials_token,
)
from .token_validation import TokenValidationConfig, validate_token
from .userinfo import UserInfoRequest, UserInfoResponse, get_userinfo


__all__ = [
    # HTTP Client
    "AsyncHTTPClient",
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
    "build_authorization_url",
    "generate_code_challenge",
    "generate_code_verifier",
    "generate_pkce_pair",
    "get_discovery_document",
    "get_jwks",
    "get_userinfo",
    "jwks_from_dict",
    "parse_authorize_callback_response",
    "request_authorization_code_token",
    "request_client_credentials_token",
    "validate_authorize_callback_state",
    "validate_token",
]
