import pytest

from py_identity_model import (
    ClientCredentialsTokenRequest,
    TokenValidationConfig,
    request_client_credentials_token,
    validate_token,
)
from py_identity_model.exceptions import FailedResponseAccessError


# JWT format: three dot-separated segments
JWT_SEGMENT_SEPARATOR_COUNT = 2


def test_request_client_credentials_token_is_successful(
    test_config, token_endpoint
):
    """Test successful token request using cached fixtures."""
    client_creds_req = ClientCredentialsTokenRequest(
        client_id=test_config["TEST_CLIENT_ID"],
        client_secret=test_config["TEST_CLIENT_SECRET"],
        address=token_endpoint,
        scope=test_config["TEST_SCOPE"],
    )
    client_creds_token = request_client_credentials_token(client_creds_req)

    assert client_creds_token
    assert client_creds_token.is_successful
    assert client_creds_token.token


def test_request_client_credentials_token_fails_invalid_credentials(
    test_config, token_endpoint
):
    """Test that token request fails with invalid client credentials."""
    client_creds_token = request_client_credentials_token(
        ClientCredentialsTokenRequest(
            client_id="bad_client_id",
            client_secret="bad_client_secret",
            address=token_endpoint,
            scope=test_config["TEST_SCOPE"],
        ),
    )

    assert client_creds_token
    assert client_creds_token.is_successful is False
    assert client_creds_token.error
    with pytest.raises(FailedResponseAccessError):
        _ = client_creds_token.token


def test_request_client_credentials_token_fails_invalid_scope(
    test_config, token_endpoint
):
    """Test token request with invalid scope.

    Some providers (e.g., Ory) reject invalid scopes with an error response.
    Others (e.g., Descope) accept any scope and return a token regardless.
    This test verifies the request completes and returns a consistent response.
    """
    client_creds_token = request_client_credentials_token(
        ClientCredentialsTokenRequest(
            client_id=test_config["TEST_CLIENT_ID"],
            client_secret=test_config["TEST_CLIENT_SECRET"],
            address=token_endpoint,
            scope="invalid_scope_that_does_not_exist",
        ),
    )

    assert client_creds_token
    if client_creds_token.is_successful:
        # Provider accepts unknown scopes (e.g., Descope)
        assert client_creds_token.token is not None
    else:
        # Provider rejects unknown scopes (e.g., Ory)
        assert client_creds_token.error
        with pytest.raises(FailedResponseAccessError):
            _ = client_creds_token.token


def test_request_client_credentials_token_fails_invalid_endpoint(
    test_config, token_endpoint
):
    """Test that token request fails with invalid endpoint."""
    # Use clearly invalid endpoint URL by appending invalid path
    invalid_endpoint = (
        token_endpoint.rstrip("/") + "/invalid/endpoint/that/does/not/exist"
    )

    client_creds_token = request_client_credentials_token(
        ClientCredentialsTokenRequest(
            client_id=test_config["TEST_CLIENT_ID"],
            client_secret=test_config["TEST_CLIENT_SECRET"],
            address=invalid_endpoint,
            scope=test_config["TEST_SCOPE"],
        ),
    )

    assert client_creds_token
    assert client_creds_token.is_successful is False
    assert client_creds_token.error


@pytest.mark.integration
class TestJwtAccessToken:
    """Test JWT-format access token features."""

    def test_jwt_access_token_structure(self, jwt_access_token):
        """JWT access token has correct structure."""
        assert "access_token" in jwt_access_token
        access_token = jwt_access_token["access_token"]
        assert access_token.count(".") == JWT_SEGMENT_SEPARATOR_COUNT, (
            "Expected JWT format"
        )

    def test_jwt_access_token_custom_claims(
        self, jwt_access_token, jwt_signing_key, issuer
    ):
        """JWT contains Descope-style dct/tenants claims.

        Skips if provider does not inject custom claims.
        """
        key_dict, alg = jwt_signing_key
        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=[alg],
            issuer=issuer,
            options={
                "verify_aud": False,
                "require_aud": False,
            },
        )
        decoded = validate_token(jwt_access_token["access_token"], config)

        if "dct" not in decoded or "tenants" not in decoded:
            pytest.skip("Provider does not include custom dct/tenants claims")

        assert decoded["dct"] == "test-tenant-1"
        assert "test-tenant-1" in decoded["tenants"]
        assert "test-tenant-2" in decoded["tenants"]
        assert "admin" in decoded["tenants"]["test-tenant-1"]["roles"]
        assert (
            "projects.read"
            in decoded["tenants"]["test-tenant-2"]["permissions"]
        )
