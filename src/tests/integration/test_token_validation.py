import datetime

import pytest

from py_identity_model import (
    PyIdentityModelException,
    TokenValidationConfig,
    validate_token,
)
from py_identity_model.exceptions import (
    ConfigurationException,
    TokenExpiredException,
    TokenValidationException,
)
from py_identity_model.sync.token_validation import (
    _get_disco_response,
    _get_jwks_response,
)


# Token validation options - only override defaults where needed
DEFAULT_OPTIONS = {
    "verify_aud": False,  # Audience validation disabled for these tests
    "require_aud": False,
}


def test_token_validation_expired_token(test_config):
    """Test expired token validation using cached config."""
    with pytest.raises(TokenExpiredException):
        validate_token(
            jwt=test_config["TEST_EXPIRED_TOKEN"],
            disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
            token_validation_config=TokenValidationConfig(
                perform_disco=True,
                options=DEFAULT_OPTIONS,
            ),
        )


def test_token_validation_succeeds(test_config, client_credentials_token):
    """Test token validation using cached fixtures."""
    assert client_credentials_token.token is not None

    validation_config = TokenValidationConfig(
        perform_disco=True,
        audience=test_config["TEST_AUDIENCE"],
        options=DEFAULT_OPTIONS,
    )

    claims = validate_token(
        jwt=client_credentials_token.token["access_token"],
        disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
        token_validation_config=validation_config,
    )
    assert claims
    assert claims["iss"]
    assert claims["iat"]
    assert claims["exp"]


def test_token_validation_with_invalid_config_throws_exception(
    test_config, client_credentials_token
):
    """Test invalid config using cached fixtures."""
    assert client_credentials_token.token is not None

    validation_config = TokenValidationConfig(
        perform_disco=False,
        audience=test_config["TEST_AUDIENCE"],
        options=DEFAULT_OPTIONS,
    )

    with pytest.raises(ConfigurationException):
        validate_token(
            jwt=client_credentials_token.token["access_token"],
            disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
            token_validation_config=validation_config,
        )


def test_cache_succeeds(test_config, client_credentials_token):
    """Test caching using cached fixtures."""
    assert client_credentials_token.token is not None

    validation_config = TokenValidationConfig(
        perform_disco=True,
        audience=test_config["TEST_AUDIENCE"],
        options=DEFAULT_OPTIONS,
    )

    for _ in range(5):
        validate_token(
            jwt=client_credentials_token.token["access_token"],
            disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
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


def test_benchmark_validation(test_config, client_credentials_token):
    """Test benchmark using cached fixtures."""
    assert client_credentials_token.token is not None
    validation_config = TokenValidationConfig(
        perform_disco=True,
        audience=test_config["TEST_AUDIENCE"],
        options=DEFAULT_OPTIONS,
    )
    start_time = datetime.datetime.now(tz=datetime.UTC)

    for _ in range(100):
        validate_token(
            jwt=client_credentials_token.token["access_token"],
            disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
            token_validation_config=validation_config,
        )
    elapsed_time = datetime.datetime.now(tz=datetime.UTC) - start_time
    print(elapsed_time)
    assert elapsed_time.total_seconds() < 1


def test_claim_validation_function_succeeds(
    test_config, client_credentials_token
):
    """Test claim validation success using cached fixtures."""
    assert client_credentials_token.token is not None

    def validate_claims(token: dict):
        # Do some token validation here
        # and raise an exception if the validation fails
        pass

    validation_config = TokenValidationConfig(
        perform_disco=True,
        audience=test_config["TEST_AUDIENCE"],
        options=DEFAULT_OPTIONS,
        claims_validator=validate_claims,
    )

    decoded_token = validate_token(
        jwt=client_credentials_token.token["access_token"],
        disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
        token_validation_config=validation_config,
    )

    assert decoded_token
    assert decoded_token["iss"]


def test_claim_validation_function_fails(
    test_config, client_credentials_token
):
    """Test claim validation failure using cached fixtures."""
    assert client_credentials_token.token is not None

    def validate_claims(token: dict):
        raise PyIdentityModelException("Validation failed!")

    validation_config = TokenValidationConfig(
        perform_disco=True,
        audience=test_config["TEST_AUDIENCE"],
        options=DEFAULT_OPTIONS,
        claims_validator=validate_claims,
    )

    with pytest.raises(TokenValidationException):
        validate_token(
            jwt=client_credentials_token.token["access_token"],
            disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
            token_validation_config=validation_config,
        )
