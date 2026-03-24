"""Unit tests for HTTP client dependency injection on public API functions."""

import httpx
import pytest
import respx

from py_identity_model.aio.discovery import (
    get_discovery_document as aio_get_disco,
)
from py_identity_model.aio.jwks import get_jwks as aio_get_jwks
from py_identity_model.aio.managed_client import AsyncHTTPClient
from py_identity_model.aio.token_client import (
    request_client_credentials_token as aio_request_token,
)
from py_identity_model.aio.userinfo import get_userinfo as aio_get_userinfo
from py_identity_model.core.models import (
    ClientCredentialsTokenRequest,
    DiscoveryDocumentRequest,
    JwksRequest,
    UserInfoRequest,
)
from py_identity_model.sync.discovery import (
    get_discovery_document as sync_get_disco,
)
from py_identity_model.sync.jwks import get_jwks as sync_get_jwks
from py_identity_model.sync.managed_client import HTTPClient
from py_identity_model.sync.token_client import (
    request_client_credentials_token as sync_request_token,
)
from py_identity_model.sync.userinfo import get_userinfo as sync_get_userinfo


DISCO_URL = "https://example.com/.well-known/openid-configuration"
JWKS_URL = "https://example.com/.well-known/jwks"
TOKEN_URL = "https://example.com/token"
USERINFO_URL = "https://example.com/userinfo"

DISCO_JSON = {
    "issuer": "https://example.com",
    "jwks_uri": JWKS_URL,
    "authorization_endpoint": "https://example.com/authorize",
    "token_endpoint": TOKEN_URL,
    "response_types_supported": ["code"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"],
}

JWKS_JSON = {
    "keys": [
        {"kty": "RSA", "kid": "1", "n": "test", "e": "AQAB", "use": "sig"}
    ]
}

TOKEN_JSON = {
    "access_token": "injected_token",
    "token_type": "Bearer",
    "expires_in": 3600,
}


@pytest.mark.unit
class TestSyncDI:
    """Test sync functions accept http_client parameter."""

    @respx.mock
    def test_discovery_with_injected_client(self):
        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_JSON)
        )
        with HTTPClient() as client:
            response = sync_get_disco(
                DiscoveryDocumentRequest(address=DISCO_URL),
                http_client=client,
            )
        assert response.is_successful
        assert response.issuer == "https://example.com"

    @respx.mock
    def test_jwks_with_injected_client(self):
        respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json=JWKS_JSON)
        )
        with HTTPClient() as client:
            response = sync_get_jwks(
                JwksRequest(address=JWKS_URL), http_client=client
            )
        assert response.is_successful

    @respx.mock
    def test_token_with_injected_client(self):
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=TOKEN_JSON)
        )
        with HTTPClient() as client:
            response = sync_request_token(
                ClientCredentialsTokenRequest(
                    address=TOKEN_URL,
                    client_id="id",
                    client_secret="secret",
                    scope="api",
                ),
                http_client=client,
            )
        assert response.is_successful
        assert response.token is not None
        assert response.token["access_token"] == "injected_token"

    @respx.mock
    def test_userinfo_with_injected_client(self):
        respx.get(USERINFO_URL).mock(
            return_value=httpx.Response(200, json={"sub": "user123"})
        )
        with HTTPClient() as client:
            response = sync_get_userinfo(
                UserInfoRequest(address=USERINFO_URL, token="bearer_token"),
                http_client=client,
            )
        assert response.is_successful

    @respx.mock
    def test_discovery_without_client_backward_compat(self):
        """http_client=None uses thread-local default (backward compat)."""
        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_JSON)
        )
        response = sync_get_disco(DiscoveryDocumentRequest(address=DISCO_URL))
        assert response.is_successful


@pytest.mark.unit
class TestAsyncDI:
    """Test async functions accept http_client parameter."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_discovery_with_injected_client(self):
        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_JSON)
        )
        async with AsyncHTTPClient() as client:
            response = await aio_get_disco(
                DiscoveryDocumentRequest(address=DISCO_URL),
                http_client=client,
            )
        assert response.is_successful
        assert response.issuer == "https://example.com"

    @pytest.mark.asyncio
    @respx.mock
    async def test_jwks_with_injected_client(self):
        respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json=JWKS_JSON)
        )
        async with AsyncHTTPClient() as client:
            response = await aio_get_jwks(
                JwksRequest(address=JWKS_URL), http_client=client
            )
        assert response.is_successful

    @pytest.mark.asyncio
    @respx.mock
    async def test_token_with_injected_client(self):
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=TOKEN_JSON)
        )
        async with AsyncHTTPClient() as client:
            response = await aio_request_token(
                ClientCredentialsTokenRequest(
                    address=TOKEN_URL,
                    client_id="id",
                    client_secret="secret",
                    scope="api",
                ),
                http_client=client,
            )
        assert response.is_successful
        assert response.token is not None
        assert response.token["access_token"] == "injected_token"

    @pytest.mark.asyncio
    @respx.mock
    async def test_userinfo_with_injected_client(self):
        respx.get(USERINFO_URL).mock(
            return_value=httpx.Response(200, json={"sub": "user123"})
        )
        async with AsyncHTTPClient() as client:
            response = await aio_get_userinfo(
                UserInfoRequest(address=USERINFO_URL, token="bearer_token"),
                http_client=client,
            )
        assert response.is_successful
