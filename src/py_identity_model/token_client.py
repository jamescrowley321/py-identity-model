"""Token client module - re-exports from sync for backward compatibility."""

from .sync.token_client import (
    ClientCredentialsTokenRequest,
    ClientCredentialsTokenResponse,
    request_client_credentials_token,
)


__all__ = [
    "ClientCredentialsTokenRequest",
    "ClientCredentialsTokenResponse",
    "request_client_credentials_token",
]
