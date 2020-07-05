import os

from py_identity_model import (
    ClientCredentialsTokenRequest,
    request_client_credentials_token,
    get_discovery_document,
    DiscoveryDocumentRequest,
)
from .test_utils import get_config

config = get_config()
TEST_DISCO_ADDRESS = config["TEST_DISCO_ADDRESS"]
TEST_CLIENT_ID = config["TEST_CLIENT_ID"]
TEST_CLIENT_SECRET = config["TEST_CLIENT_SECRET"]
TEST_SCOPE = config["TEST_SCOPE"]


# TODO: failure conditions
def test_request_client_credentials_token_is_successful():
    disco_doc_response = get_discovery_document(
        DiscoveryDocumentRequest(address=TEST_DISCO_ADDRESS)
    )

    client_creds_req = ClientCredentialsTokenRequest(
        client_id=TEST_CLIENT_ID,
        client_secret=TEST_CLIENT_SECRET,
        address=disco_doc_response.token_endpoint,
        scope=TEST_SCOPE,
    )
    client_creds_token = request_client_credentials_token(client_creds_req)

    assert client_creds_token
    assert client_creds_token.is_successful
    assert client_creds_token.token


def test_request_client_credentials_token_fails():
    disco_doc_response = get_discovery_document(
        DiscoveryDocumentRequest(address=TEST_DISCO_ADDRESS)
    )

    client_creds_req = ClientCredentialsTokenRequest(
        client_id="bad_client_id",
        client_secret="bad_client_secret",
        address=disco_doc_response.token_endpoint,
        scope=TEST_SCOPE,
    )
    client_creds_token = request_client_credentials_token(client_creds_req)

    assert client_creds_token
    assert client_creds_token.is_successful is False
    print(client_creds_token.error)
    assert client_creds_token.error
