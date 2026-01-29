from py_identity_model import (
    ClientCredentialsTokenRequest,
    request_client_credentials_token,
)


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
    assert client_creds_token.token is None


def test_request_client_credentials_token_fails_invalid_scope(
    test_config, token_endpoint
):
    """Test that token request fails with invalid scope."""
    client_creds_token = request_client_credentials_token(
        ClientCredentialsTokenRequest(
            client_id=test_config["TEST_CLIENT_ID"],
            client_secret=test_config["TEST_CLIENT_SECRET"],
            address=token_endpoint,
            scope="invalid_scope_that_does_not_exist",
        ),
    )

    assert client_creds_token
    assert client_creds_token.is_successful is False
    assert client_creds_token.error
    assert client_creds_token.token is None


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
