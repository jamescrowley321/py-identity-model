"""Async tests for aio.jwks module."""

import httpx
import pytest
import respx

from py_identity_model.aio.jwks import JwksRequest, get_jwks


@pytest.mark.asyncio
class TestAsyncJwks:
    @respx.mock
    async def test_async_get_jwks_success(self):
        """Test successful async JWKS fetch"""
        url = "https://example.com/jwks"
        respx.get(url).mock(
            return_value=httpx.Response(
                200,
                json={
                    "keys": [
                        {
                            "kty": "RSA",
                            "use": "sig",
                            "alg": "RS256",
                            "kid": "key1",
                            "n": "example_n",
                            "e": "AQAB",
                        },
                        {
                            "kty": "EC",
                            "use": "sig",
                            "alg": "ES256",
                            "kid": "key2",
                            "crv": "P-256",
                            "x": "example_x",
                            "y": "example_y",
                        },
                    ],
                },
            )
        )

        request = JwksRequest(address=url)
        result = await get_jwks(request)

        assert result.is_successful is True
        assert result.keys is not None
        assert len(result.keys) == 2
        assert result.keys[0].kty == "RSA"
        assert result.keys[0].kid == "key1"
        assert result.keys[1].kty == "EC"
        assert result.keys[1].kid == "key2"

    @respx.mock
    async def test_async_get_jwks_http_error(self):
        """Test async JWKS fetch with HTTP error"""
        url = "https://example.com/jwks"
        respx.get(url).mock(
            return_value=httpx.Response(404, content=b"Not Found")
        )

        request = JwksRequest(address=url)
        result = await get_jwks(request)

        assert result.is_successful is False
        assert result.keys is None
        assert result.error is not None
        assert "404" in result.error

    @respx.mock
    async def test_async_get_jwks_network_error(self):
        """Test async JWKS fetch with network error"""
        url = "https://example.com/jwks"
        respx.get(url).mock(side_effect=httpx.ConnectError("Network error"))

        request = JwksRequest(address=url)
        result = await get_jwks(request)

        assert result.is_successful is False
        assert result.error is not None
        assert "Network error" in result.error
