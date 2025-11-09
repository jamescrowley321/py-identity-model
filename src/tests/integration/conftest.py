"""Shared fixtures for integration tests with caching and retry logic."""

import httpx
import pytest
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from py_identity_model import (
    ClientCredentialsTokenRequest,
    DiscoveryDocumentRequest,
    JwksRequest,
    get_discovery_document,
    get_jwks,
    request_client_credentials_token,
)

from .test_utils import get_config


# Retry decorator for rate limit handling
def retry_on_rate_limit():
    """Retry decorator that handles HTTP 429 rate limiting."""
    return retry(
        retry=retry_if_exception_type(httpx.HTTPStatusError),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        stop=stop_after_attempt(3),
        reraise=True,
    )


@pytest.fixture(scope="session")
def test_config(env_file):
    """
    Session-scoped fixture providing test configuration.

    This is loaded once per test session and shared across all workers.
    """
    return get_config(env_file)


@pytest.fixture(scope="session")
def discovery_document(test_config):
    """
    Session-scoped fixture providing cached discovery document.

    Fetches the discovery document once and caches it for all tests.
    Includes retry logic to handle transient rate limits.
    """

    @retry_on_rate_limit()
    def fetch_discovery():
        disco_doc_req = DiscoveryDocumentRequest(
            address=test_config["TEST_DISCO_ADDRESS"]
        )
        response = get_discovery_document(disco_doc_req)

        # If we got a 429, check the response and raise to trigger retry
        if not response.is_successful and "429" in str(response.error):
            request = httpx.Request("GET", test_config["TEST_DISCO_ADDRESS"])
            raise httpx.HTTPStatusError(
                "Rate limited", request=request, response=httpx.Response(429)
            )

        return response

    return fetch_discovery()


@pytest.fixture(scope="session")
def jwks_response(test_config):
    """
    Session-scoped fixture providing cached JWKS response.

    Fetches the JWKS once and caches it for all tests.
    Includes retry logic to handle transient rate limits.
    """

    @retry_on_rate_limit()
    def fetch_jwks():
        jwks_req = JwksRequest(address=test_config["TEST_JWKS_ADDRESS"])
        response = get_jwks(jwks_req)

        # If we got a 429, check the response and raise to trigger retry
        if not response.is_successful and "429" in str(response.error):
            request = httpx.Request("GET", test_config["TEST_JWKS_ADDRESS"])
            raise httpx.HTTPStatusError(
                "Rate limited", request=request, response=httpx.Response(429)
            )

        return response

    return fetch_jwks()


@pytest.fixture(scope="session")
def token_endpoint(discovery_document):
    """Provide the token endpoint from cached discovery document."""
    return discovery_document.token_endpoint


@pytest.fixture(scope="session")
def jwks_uri(discovery_document):
    """Provide the JWKS URI from cached discovery document."""
    return discovery_document.jwks_uri


@pytest.fixture(scope="session")
def issuer(discovery_document):
    """Provide the issuer from cached discovery document."""
    return discovery_document.issuer


@pytest.fixture(scope="session")
def client_credentials_token(test_config, token_endpoint):
    """
    Session-scoped fixture providing a cached client credentials token.

    Generates one token per test session and shares it across all tests.
    Includes retry logic to handle transient rate limits.
    """

    @retry_on_rate_limit()
    def fetch_token():
        response = request_client_credentials_token(
            ClientCredentialsTokenRequest(
                client_id=test_config["TEST_CLIENT_ID"],
                client_secret=test_config["TEST_CLIENT_SECRET"],
                address=token_endpoint,
                scope=test_config["TEST_SCOPE"],
            )
        )

        # If we got a 429, check the response and raise to trigger retry
        if not response.is_successful and "429" in str(response.error):
            request = httpx.Request("POST", token_endpoint)
            raise httpx.HTTPStatusError(
                "Rate limited", request=request, response=httpx.Response(429)
            )

        return response

    return fetch_token()
