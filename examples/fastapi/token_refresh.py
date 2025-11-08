"""
Token refresh utilities for FastAPI applications.

This module provides utilities for handling OAuth2 token refresh flows
in FastAPI applications using py-identity-model.
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import httpx

from py_identity_model import (
    DiscoveryDocumentRequest,
    PyIdentityModelException,
    get_discovery_document,
)


@dataclass
class RefreshTokenRequest:
    """Request parameters for refreshing an OAuth2 token."""

    refresh_token: str
    client_id: str
    client_secret: str | None = None
    scope: str | None = None


@dataclass
class RefreshTokenResponse:
    """Response from a token refresh request."""

    is_successful: bool
    access_token: str | None = None
    refresh_token: str | None = None
    expires_in: int | None = None
    token_type: str | None = None
    scope: str | None = None
    error: str | None = None
    error_description: str | None = None


async def refresh_access_token(
    discovery_url: str,
    request: RefreshTokenRequest,
) -> RefreshTokenResponse:
    """
    Refresh an access token using a refresh token.

    Args:
        discovery_url: The OpenID Connect discovery document URL
        request: The refresh token request parameters

    Returns:
        RefreshTokenResponse: The response containing the new tokens or error

    Example:
        ```python
        refresh_request = RefreshTokenRequest(
            refresh_token="existing_refresh_token",
            client_id="my-client-id",
            client_secret="my-client-secret",
        )

        response = await refresh_access_token(
            "https://auth.example.com/.well-known/openid-configuration",
            refresh_request,
        )

        if response.is_successful:
            new_access_token = response.access_token
            new_refresh_token = response.refresh_token
        else:
            print(f"Refresh failed: {response.error}")
        ```
    """
    try:
        # Get discovery document to find token endpoint
        disco_request = DiscoveryDocumentRequest(address=discovery_url)
        disco_response = get_discovery_document(disco_request)

        if not disco_response.is_successful:
            return RefreshTokenResponse(
                is_successful=False,
                error="discovery_failed",
                error_description=disco_response.error,
            )

        token_endpoint = disco_response.token_endpoint
        if not token_endpoint:
            return RefreshTokenResponse(
                is_successful=False,
                error="invalid_discovery",
                error_description="Token endpoint not found in discovery document",
            )

        # Prepare token request
        data = {
            "grant_type": "refresh_token",
            "refresh_token": request.refresh_token,
            "client_id": request.client_id,
        }

        if request.client_secret:
            data["client_secret"] = request.client_secret

        if request.scope:
            data["scope"] = request.scope

        # Make token request
        async with httpx.AsyncClient() as client:
            response = await client.post(
                token_endpoint,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

        if response.status_code != 200:
            error_data = response.json() if response.text else {}
            return RefreshTokenResponse(
                is_successful=False,
                error=error_data.get("error", "token_request_failed"),
                error_description=error_data.get(
                    "error_description",
                    f"HTTP {response.status_code}",
                ),
            )

        # Parse successful response
        token_data = response.json()
        return RefreshTokenResponse(
            is_successful=True,
            access_token=token_data.get("access_token"),
            refresh_token=token_data.get("refresh_token"),
            expires_in=token_data.get("expires_in"),
            token_type=token_data.get("token_type", "Bearer"),
            scope=token_data.get("scope"),
        )

    except PyIdentityModelException as e:
        return RefreshTokenResponse(
            is_successful=False,
            error="py_identity_model_error",
            error_description=str(e),
        )
    except Exception as e:
        return RefreshTokenResponse(
            is_successful=False,
            error="unexpected_error",
            error_description=str(e),
        )


class TokenManager:
    """
    Manages access tokens with automatic refresh capabilities.

    This class helps manage the lifecycle of access tokens by automatically
    refreshing them when they expire or are about to expire.

    Example:
        ```python
        manager = TokenManager(
            discovery_url="https://auth.example.com/.well-known/openid-configuration",
            client_id="my-client-id",
            client_secret="my-client-secret",
        )

        # Set initial tokens
        manager.set_tokens(
            access_token="initial_access_token",
            refresh_token="initial_refresh_token",
            expires_in=3600,
        )

        # Get current access token (will auto-refresh if expired)
        token = await manager.get_access_token()
        ```
    """

    def __init__(
        self,
        discovery_url: str,
        client_id: str,
        client_secret: str | None = None,
        refresh_before_seconds: int = 300,
    ):
        """
        Initialize the token manager.

        Args:
            discovery_url: The OpenID Connect discovery document URL
            client_id: The OAuth2 client ID
            client_secret: The OAuth2 client secret (optional for public clients)
            refresh_before_seconds: Refresh token this many seconds before expiry (default: 300)
        """
        self.discovery_url = discovery_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.refresh_before_seconds = refresh_before_seconds

        self._access_token: str | None = None
        self._refresh_token: str | None = None
        self._expires_at: datetime | None = None

    def set_tokens(
        self,
        access_token: str,
        refresh_token: str | None = None,
        expires_in: int | None = None,
    ) -> None:
        """
        Set the current tokens.

        Args:
            access_token: The access token
            refresh_token: The refresh token (optional)
            expires_in: Token expiry time in seconds (optional)
        """
        self._access_token = access_token
        self._refresh_token = refresh_token

        if expires_in:
            self._expires_at = datetime.now(UTC) + timedelta(
                seconds=expires_in,
            )
        else:
            self._expires_at = None

    def is_token_expired(self) -> bool:
        """
        Check if the current access token is expired or about to expire.

        Returns:
            bool: True if the token is expired or will expire soon
        """
        if not self._expires_at:
            return False

        # Consider token expired if it will expire within refresh_before_seconds
        return datetime.now(UTC) >= (
            self._expires_at - timedelta(seconds=self.refresh_before_seconds)
        )

    async def get_access_token(self) -> str | None:
        """
        Get the current access token, refreshing if necessary.

        Returns:
            Optional[str]: The access token, or None if refresh failed

        Raises:
            PyIdentityModelException: If token refresh fails
        """
        # If token is not expired, return it
        if self._access_token and not self.is_token_expired():
            return self._access_token

        # Token is expired or about to expire, attempt refresh
        if not self._refresh_token:
            raise PyIdentityModelException(
                "Token expired and no refresh token available",
            )

        response = await refresh_access_token(
            self.discovery_url,
            RefreshTokenRequest(
                refresh_token=self._refresh_token,
                client_id=self.client_id,
                client_secret=self.client_secret,
            ),
        )

        if not response.is_successful:
            raise PyIdentityModelException(
                f"Token refresh failed: {response.error_description}",
            )

        # Ensure we have an access token
        if not response.access_token:
            raise PyIdentityModelException(
                "Token refresh succeeded but no access token returned",
            )

        # Update stored tokens
        self.set_tokens(
            access_token=response.access_token,
            refresh_token=response.refresh_token or self._refresh_token,
            expires_in=response.expires_in,
        )

        return self._access_token

    @property
    def access_token(self) -> str | None:
        """Get the current access token without refreshing."""
        return self._access_token

    @property
    def refresh_token(self) -> str | None:
        """Get the current refresh token."""
        return self._refresh_token
