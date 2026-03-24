"""
Core module for py-identity-model.

This module contains shared business logic, models, validators, and utilities
that are used by both sync and async implementations.
"""

from .authorize_response import (
    AuthorizeCallbackResponse,
    parse_authorize_callback_response,
)
from .http_utils import (
    DEFAULT_HTTP_TIMEOUT,
    DEFAULT_RETRY_BASE_DELAY,
    DEFAULT_RETRY_MAX_ATTEMPTS,
)
from .jwt_helpers import decode_and_validate_jwt
from .models import (
    BaseRequest,
    BaseResponse,
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
)
from .parsers import get_public_key_from_jwk, jwks_from_dict
from .state_validation import (
    AuthorizeCallbackValidationResult,
    StateValidationResult,
    validate_authorize_callback_state,
)
from .validators import (
    validate_https_url,
    validate_issuer,
    validate_parameter_values,
    validate_required_parameters,
    validate_token_config,
)


__all__ = [
    # From http_utils
    "DEFAULT_HTTP_TIMEOUT",
    "DEFAULT_RETRY_BASE_DELAY",
    "DEFAULT_RETRY_MAX_ATTEMPTS",
    # From authorize_response
    "AuthorizeCallbackResponse",
    # From state_validation
    "AuthorizeCallbackValidationResult",
    # From models (base classes)
    "BaseRequest",
    "BaseResponse",
    # From models
    "ClientCredentialsTokenRequest",
    "ClientCredentialsTokenResponse",
    "DiscoveryDocumentRequest",
    "DiscoveryDocumentResponse",
    "JsonWebAlgorithmsKeyTypes",
    "JsonWebKey",
    "JsonWebKeyParameterNames",
    "JwksRequest",
    "JwksResponse",
    "StateValidationResult",
    "TokenValidationConfig",
    # From jwt_helpers
    "decode_and_validate_jwt",
    # From parsers
    "get_public_key_from_jwk",
    "jwks_from_dict",
    "parse_authorize_callback_response",
    "validate_authorize_callback_state",
    # From validators
    "validate_https_url",
    "validate_issuer",
    "validate_parameter_values",
    "validate_required_parameters",
    "validate_token_config",
]
