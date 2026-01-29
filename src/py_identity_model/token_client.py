"""Token client module - re-exports from sync for backward compatibility."""

from .sync.token_client import (  # pragma: no cover
    ClientCredentialsTokenRequest,
    ClientCredentialsTokenResponse,
    request_client_credentials_token,
)


__all__ = [  # pragma: no cover
    "ClientCredentialsTokenRequest",
    "ClientCredentialsTokenResponse",
    "request_client_credentials_token",
]
