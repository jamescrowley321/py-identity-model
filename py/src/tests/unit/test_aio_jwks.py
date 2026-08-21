"""Async tests for aio.jwks module."""

import httpx
import pytest
import respx

from py_identity_model.aio.jwks import JwksRequest, get_jwks
from py_identity_model.core.discovery_policy import DiscoveryPolicy
from py_identity_model.exceptions import FailedResponseAccessError


# Expected JWKS key count
EXPECTED_KEY_COUNT = 2


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
        assert len(result.keys) == EXPECTED_KEY_COUNT
        assert result.keys[0].kty == "RSA"
        assert result.keys[0].kid == "key1"
        assert result.keys[1].kty == "EC"
        assert result.keys[1].kid == "key2"

    @respx.mock
    async def test_async_get_jwks_http_error(self):
        """Test async JWKS fetch with HTTP error"""
        url = "https://example.com/jwks"
        respx.get(url).mock(return_value=httpx.Response(404, content=b"Not Found"))

        request = JwksRequest(address=url)
        result = await get_jwks(request)

        assert result.is_successful is False
        with pytest.raises(FailedResponseAccessError):
            _ = result.keys
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


@pytest.mark.asyncio
class TestAsyncGetJwksSchemeValidation:
    """Async mirror of the sync scheme-validation regression coverage for #380."""

    @pytest.mark.parametrize(
        "url",
        [
            "ftp://example.com/jwks",
            "file:///etc/passwd",
            "data:application/json,{}",
            "javascript:alert(1)",
        ],
    )
    @respx.mock(assert_all_called=False)
    async def test_rejects_non_http_schemes(self, url):
        result = await get_jwks(JwksRequest(address=url))

        assert result.is_successful is False
        assert result.error is not None
        assert "Invalid JWKS endpoint URL" in result.error

    @respx.mock
    async def test_https_is_accepted(self):
        url = "https://example.com/jwks"
        respx.get(url).mock(
            return_value=httpx.Response(200, json={"keys": []}),
        )
        result = await get_jwks(JwksRequest(address=url))
        assert result.is_successful is True

    @respx.mock(assert_all_called=False)
    async def test_http_rejected_under_default_policy(self):
        url = "http://example.com/jwks"
        route = respx.get(url)
        result = await get_jwks(JwksRequest(address=url))

        assert result.is_successful is False
        assert result.error is not None
        assert "HTTPS is required" in result.error
        assert route.call_count == 0

    @respx.mock
    async def test_http_loopback_allowed_under_default_policy(self):
        url = "http://127.0.0.1:8080/jwks"
        respx.get(url).mock(
            return_value=httpx.Response(200, json={"keys": []}),
        )
        result = await get_jwks(JwksRequest(address=url))
        assert result.is_successful is True

    @respx.mock
    async def test_http_allowed_when_policy_disables_require_https(self):
        url = "http://example.com/jwks"
        respx.get(url).mock(
            return_value=httpx.Response(200, json={"keys": []}),
        )
        policy = DiscoveryPolicy(require_https=False)
        result = await get_jwks(JwksRequest(address=url, policy=policy))
        assert result.is_successful is True
