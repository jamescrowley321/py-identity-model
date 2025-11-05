from py_identity_model import (
    ClientCredentialsTokenRequest,
    DiscoveryDocumentRequest,
    get_discovery_document,
    request_client_credentials_token,
)

from .test_utils import get_config


def test_request_client_credentials_token_is_successful(env_file):
    config = get_config(env_file)
    disco_doc_response = get_discovery_document(
        DiscoveryDocumentRequest(address=config["TEST_DISCO_ADDRESS"]),
    )
    assert disco_doc_response.token_endpoint is not None

    client_creds_req = ClientCredentialsTokenRequest(
        client_id=config["TEST_CLIENT_ID"],
        client_secret=config["TEST_CLIENT_SECRET"],
        address=disco_doc_response.token_endpoint,
        scope=config["TEST_SCOPE"],
    )
    client_creds_token = request_client_credentials_token(client_creds_req)

    assert client_creds_token
    assert client_creds_token.is_successful
    assert client_creds_token.token


def test_request_client_credentials_token_fails_invalid_credentials(env_file):
    """Test that token request fails with invalid client credentials."""
    config = get_config(env_file)
    disco_doc_response = get_discovery_document(
        DiscoveryDocumentRequest(address=config["TEST_DISCO_ADDRESS"]),
    )
    assert disco_doc_response.token_endpoint is not None

    client_creds_token = request_client_credentials_token(
        ClientCredentialsTokenRequest(
            client_id="bad_client_id",
            client_secret="bad_client_secret",
            address=disco_doc_response.token_endpoint,
            scope=config["TEST_SCOPE"],
        ),
    )

    assert client_creds_token
    assert client_creds_token.is_successful is False
    assert client_creds_token.error
    assert client_creds_token.token is None


def test_request_client_credentials_token_fails_invalid_scope(env_file):
    """Test that token request fails with invalid scope."""
    config = get_config(env_file)
    disco_doc_response = get_discovery_document(
        DiscoveryDocumentRequest(address=config["TEST_DISCO_ADDRESS"]),
    )
    assert disco_doc_response.token_endpoint is not None

    client_creds_token = request_client_credentials_token(
        ClientCredentialsTokenRequest(
            client_id=config["TEST_CLIENT_ID"],
            client_secret=config["TEST_CLIENT_SECRET"],
            address=disco_doc_response.token_endpoint,
            scope="invalid_scope_that_does_not_exist",
        ),
    )

    assert client_creds_token
    assert client_creds_token.is_successful is False
    assert client_creds_token.error
    assert client_creds_token.token is None


def test_request_client_credentials_token_fails_invalid_endpoint(env_file):
    """Test that token request fails with invalid endpoint."""
    config = get_config(env_file)
    disco_doc_response = get_discovery_document(
        DiscoveryDocumentRequest(address=config["TEST_DISCO_ADDRESS"]),
    )
    assert disco_doc_response.token_endpoint is not None

    # Use clearly invalid endpoint URL by appending invalid path
    invalid_endpoint = (
        disco_doc_response.token_endpoint.rstrip("/")
        + "/invalid/endpoint/that/does/not/exist"
    )

    client_creds_token = request_client_credentials_token(
        ClientCredentialsTokenRequest(
            client_id=config["TEST_CLIENT_ID"],
            client_secret=config["TEST_CLIENT_SECRET"],
            address=invalid_endpoint,
            scope=config["TEST_SCOPE"],
        ),
    )

    assert client_creds_token
    assert client_creds_token.is_successful is False
    assert client_creds_token.error
