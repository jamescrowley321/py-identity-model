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
