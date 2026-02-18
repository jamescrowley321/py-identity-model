"""Integration tests for UserInfo endpoint operations."""

from py_identity_model import (
    UserInfoRequest,
    get_userinfo,
)


def test_discovery_document_has_userinfo_endpoint(discovery_document):
    """Test that the discovery document includes a userinfo_endpoint."""
    assert discovery_document.is_successful
    assert discovery_document.userinfo_endpoint
    assert discovery_document.userinfo_endpoint.startswith("https://")


def test_get_userinfo_with_client_credentials_token(
    userinfo_endpoint, client_credentials_token
):
    """Test UserInfo with a client credentials token.

    Client credentials tokens represent machine-to-machine communication
    without a user context. Behavior varies by provider:
    - Some providers (e.g. Ory) return claims (aud, iat, iss)
    - Some providers (e.g. Duende IdentityServer) reject the request

    Either outcome is valid; we verify the response is well-formed.
    """
    assert client_credentials_token.token is not None
    assert userinfo_endpoint is not None

    request = UserInfoRequest(
        address=userinfo_endpoint,
        token=client_credentials_token.token["access_token"],
    )
    response = get_userinfo(request)

    if response.is_successful:
        # Provider returned claims for client credentials token
        assert response.claims is not None or response.raw is not None
        assert response.error is None
    else:
        # Provider rejected client credentials token (no user context)
        assert response.error is not None


def test_get_userinfo_with_invalid_token(userinfo_endpoint):
    """Test that UserInfo fails with an invalid token."""
    assert userinfo_endpoint is not None

    request = UserInfoRequest(
        address=userinfo_endpoint,
        token="invalid-token-that-does-not-exist",
    )
    response = get_userinfo(request)

    assert response.is_successful is False
    assert response.error is not None


def test_get_userinfo_with_invalid_endpoint(client_credentials_token):
    """Test that UserInfo fails with an invalid endpoint."""
    assert client_credentials_token.token is not None

    request = UserInfoRequest(
        address="https://invalid.example.com/userinfo",
        token=client_credentials_token.token["access_token"],
    )
    response = get_userinfo(request)

    assert response.is_successful is False
    assert response.error is not None
