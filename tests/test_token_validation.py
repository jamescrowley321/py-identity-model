import pytest

from py_identity_model import (
    PyIdentityModelException,
    validate_token,
    get_discovery_document,
    DiscoveryDocumentRequest,
    ClientCredentialsTokenRequest,
    request_client_credentials_token,
    TokenValidationConfig,
)
from .test_utils import get_config

# TODO: clean this up
config = get_config()
TEST_DISCO_ADDRESS = config["TEST_DISCO_ADDRESS"]
TEST_EXPIRED_TOKEN = config["TEST_EXPIRED_TOKEN"]
TEST_CLIENT_ID = config["TEST_CLIENT_ID"]
TEST_CLIENT_SECRET = config["TEST_CLIENT_SECRET"]
TEST_SCOPE = config["TEST_SCOPE"]
TEST_AUDIENCE = config["TEST_AUDIENCE"]


def test_token_validation_expired_token():
    with pytest.raises(
        PyIdentityModelException
    ):  # TODO: Create more specific exceptions
        validate_token(
            jwt=TEST_EXPIRED_TOKEN,
            disco_doc_address=TEST_DISCO_ADDRESS,
            token_validation_config=TokenValidationConfig(perform_disco=True),
        )


def test_token_validation_succeeds():
    disco_doc_response = get_discovery_document(
        DiscoveryDocumentRequest(address=TEST_DISCO_ADDRESS)
    )

    client_creds_req = ClientCredentialsTokenRequest(
        client_id=TEST_CLIENT_ID,
        client_secret=TEST_CLIENT_SECRET,
        address=disco_doc_response.token_endpoint,
        scope=TEST_SCOPE,
    )
    client_creds_response = request_client_credentials_token(client_creds_req)

    validation_options = {
        "verify_signature": True,
        "verify_aud": True,
        "verify_iat": True,
        "verify_exp": True,
        "verify_nbf": True,
        "verify_iss": True,
        "verify_sub": True,
        "verify_jti": True,
        "verify_at_hash": True,
        "require_aud": False,
        "require_iat": False,
        "require_exp": False,
        "require_nbf": False,
        "require_iss": False,
        "require_sub": False,
        "require_jti": False,
        "require_at_hash": False,
        "leeway": 0,
    }

    # TODO: move to config
    validation_config = TokenValidationConfig(
        perform_disco=True, audience=TEST_AUDIENCE, options=validation_options
    )

    claims = validate_token(
        jwt=client_creds_response.token["access_token"],
        disco_doc_address=TEST_DISCO_ADDRESS,
        token_validation_config=validation_config,
    )
    assert claims


# TODO: more tests to make sure options passed will work with a few common scenarios
# TODO: update documentation
