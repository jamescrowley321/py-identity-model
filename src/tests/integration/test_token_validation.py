import datetime

import pytest
from jwt import ExpiredSignatureError

from py_identity_model import (
    ClientCredentialsTokenRequest,
    DiscoveryDocumentRequest,
    PyIdentityModelException,
    TokenValidationConfig,
    get_discovery_document,
    request_client_credentials_token,
    validate_token,
)
from py_identity_model.token_validation import (
    _get_disco_response,
    _get_jwks_response,
)

from .test_utils import get_config

# TODO: clean this up

DEFAULT_OPTIONS = {
    "verify_signature": True,
    "verify_aud": False,
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


def _generate_token(config):
    disco_doc_response = get_discovery_document(
        DiscoveryDocumentRequest(address=config["TEST_DISCO_ADDRESS"])
    )
    assert disco_doc_response.token_endpoint is not None
    client_creds_req = ClientCredentialsTokenRequest(
        client_id=config["TEST_CLIENT_ID"],
        client_secret=config["TEST_CLIENT_SECRET"],
        address=disco_doc_response.token_endpoint,
        scope=config["TEST_SCOPE"],
    )
    client_creds_response = request_client_credentials_token(client_creds_req)
    return client_creds_response


def test_token_validation_expired_token(env_file):
    config = get_config(env_file)
    with pytest.raises(ExpiredSignatureError):
        validate_token(
            jwt=config["TEST_EXPIRED_TOKEN"],
            disco_doc_address=config["TEST_DISCO_ADDRESS"],
            token_validation_config=TokenValidationConfig(
                perform_disco=True, options=DEFAULT_OPTIONS
            ),
        )


def test_token_validation_succeeds(env_file):
    config = get_config(env_file)
    client_creds_response = _generate_token(config)
    assert client_creds_response.token is not None

    validation_config = TokenValidationConfig(
        perform_disco=True,
        audience=config["TEST_AUDIENCE"],
        options=DEFAULT_OPTIONS,
    )

    claims = validate_token(
        jwt=client_creds_response.token["access_token"],
        disco_doc_address=config["TEST_DISCO_ADDRESS"],
        token_validation_config=validation_config,
    )
    assert claims
    assert claims["iss"]
    assert claims["iat"]
    assert claims["exp"]


def test_token_validation_with_invalid_config_throws_exception(env_file):
    config = get_config(env_file)
    client_creds_response = _generate_token(config)
    assert client_creds_response.token is not None

    validation_config = TokenValidationConfig(
        perform_disco=False,
        audience=config["TEST_AUDIENCE"],
        options=DEFAULT_OPTIONS,
    )

    with pytest.raises(PyIdentityModelException):
        validate_token(
            jwt=client_creds_response.token["access_token"],
            disco_doc_address=config["TEST_DISCO_ADDRESS"],
            token_validation_config=validation_config,
        )


def test_cache_succeeds(env_file):
    config = get_config(env_file)
    client_creds_response = _generate_token(config)
    assert client_creds_response.token is not None

    validation_config = TokenValidationConfig(
        perform_disco=True,
        audience=config["TEST_AUDIENCE"],
        options=DEFAULT_OPTIONS,
    )

    for _ in range(0, 5):
        validate_token(
            jwt=client_creds_response.token["access_token"],
            disco_doc_address=config["TEST_DISCO_ADDRESS"],
            token_validation_config=validation_config,
        )

    cache_info = _get_disco_response.cache_info()
    print(cache_info)
    assert cache_info
    assert cache_info[0] > 0

    cache_info = _get_jwks_response.cache_info()
    print(cache_info)
    assert cache_info
    assert cache_info[0] > 0


def test_benchmark_validation(env_file):
    config = get_config(env_file)
    client_creds_response = _generate_token(config)
    assert client_creds_response.token is not None
    validation_config = TokenValidationConfig(
        perform_disco=True,
        audience=config["TEST_AUDIENCE"],
        options=DEFAULT_OPTIONS,
    )
    start_time = datetime.datetime.now()

    for _ in range(0, 100):
        validate_token(
            jwt=client_creds_response.token["access_token"],
            disco_doc_address=config["TEST_DISCO_ADDRESS"],
            token_validation_config=validation_config,
        )
    elapsed_time = datetime.datetime.now() - start_time
    print(elapsed_time)
    assert elapsed_time.total_seconds() < 1


def test_claim_validation_function_succeeds(env_file):
    config = get_config(env_file)
    client_creds_response = _generate_token(config)
    assert client_creds_response.token is not None

    def validate_claims(token: dict):
        # Do some token validation here
        # and raise an exception if the validation fails
        pass

    validation_config = TokenValidationConfig(
        perform_disco=True,
        audience=config["TEST_AUDIENCE"],
        options=DEFAULT_OPTIONS,
        claims_validator=validate_claims,
    )

    decoded_token = validate_token(
        jwt=client_creds_response.token["access_token"],
        disco_doc_address=config["TEST_DISCO_ADDRESS"],
        token_validation_config=validation_config,
    )

    assert decoded_token
    assert decoded_token["iss"]


def test_claim_validation_function_fails(env_file):
    config = get_config(env_file)
    client_creds_response = _generate_token(config)
    assert client_creds_response.token is not None

    def validate_claims(token: dict):
        raise PyIdentityModelException("Validation failed!")

    validation_config = TokenValidationConfig(
        perform_disco=True,
        audience=config["TEST_AUDIENCE"],
        options=DEFAULT_OPTIONS,
        claims_validator=validate_claims,
    )

    with pytest.raises(PyIdentityModelException):
        validate_token(
            jwt=client_creds_response.token["access_token"],
            disco_doc_address=config["TEST_DISCO_ADDRESS"],
            token_validation_config=validation_config,
        )
