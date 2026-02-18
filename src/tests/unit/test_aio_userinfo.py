"""Async tests for aio.userinfo module."""

import httpx
import pytest
import respx

from py_identity_model.aio.userinfo import UserInfoRequest, get_userinfo


@pytest.mark.asyncio
class TestAsyncUserInfo:
    @respx.mock
    async def test_async_get_userinfo_json_success(self):
        """Test successful async UserInfo request with JSON response."""
        url = "https://example.com/userinfo"
        respx.get(url).mock(
            return_value=httpx.Response(
                200,
                json={
                    "sub": "248289761001",
                    "name": "Jane Doe",
                    "email": "janedoe@example.com",
                    "email_verified": True,
                },
                headers={"Content-Type": "application/json"},
            )
        )

        request = UserInfoRequest(
            address=url,
            token="test_access_token",
        )
        result = await get_userinfo(request)

        assert result.is_successful is True
        assert result.claims is not None
        assert result.claims["sub"] == "248289761001"
        assert result.claims["name"] == "Jane Doe"
        assert result.raw is None
        assert result.error is None

    @respx.mock
    async def test_async_get_userinfo_jwt_response(self):
        """Test async UserInfo request with JWT response."""
        url = "https://example.com/userinfo"
        jwt_string = (
            "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIyNDgyODk3NjEwMDEifQ.signature"
        )
        respx.get(url).mock(
            return_value=httpx.Response(
                200,
                text=jwt_string,
                headers={"Content-Type": "application/jwt"},
            )
        )

        request = UserInfoRequest(
            address=url,
            token="test_access_token",
        )
        result = await get_userinfo(request)

        assert result.is_successful is True
        assert result.raw == jwt_string
        assert result.claims is None
        assert result.error is None

    @respx.mock
    async def test_async_get_userinfo_http_error(self):
        """Test async UserInfo request with HTTP error."""
        url = "https://example.com/userinfo"
        respx.get(url).mock(
            return_value=httpx.Response(401, content=b"Unauthorized")
        )

        request = UserInfoRequest(
            address=url,
            token="expired_token",
        )
        result = await get_userinfo(request)

        assert result.is_successful is False
        assert result.claims is None
        assert result.error is not None
        assert "401" in result.error

    @respx.mock
    async def test_async_get_userinfo_network_error(self):
        """Test async UserInfo request with network error."""
        url = "https://example.com/userinfo"
        respx.get(url).mock(side_effect=httpx.ConnectError("Network error"))

        request = UserInfoRequest(
            address=url,
            token="test_access_token",
        )
        result = await get_userinfo(request)

        assert result.is_successful is False
        assert result.error is not None
        assert "Network error" in result.error
