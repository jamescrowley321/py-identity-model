"""Shared fixtures for integration tests with caching and retry logic."""

from contextlib import suppress

from filelock import FileLock
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
from py_identity_model.sync.http_client import close_http_client

from .test_utils import get_config


# Constants
RATE_LIMIT_ERROR_MESSAGE = "Rate limited"


# Retry decorator for rate limit handling
def retry_with_backoff():
    """Retry decorator that handles HTTP 429 rate limiting."""
    return retry(
        retry=retry_if_exception_type(httpx.HTTPStatusError),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        stop=stop_after_attempt(3),
        reraise=True,
    )


@pytest.fixture(scope="session")
def test_config(env_file, tmp_path_factory):
    """
    Session-scoped fixture providing test configuration.

    Uses file lock to ensure thread-safe initialization across
    pytest-xdist workers during parallel execution.
    """
    # Create a lock file in the temp directory shared across workers
    root_tmp_dir = tmp_path_factory.getbasetemp().parent
    lock_file = root_tmp_dir / "test_config.lock"

    # Use file lock to prevent race conditions during parallel execution
    with FileLock(str(lock_file)):
        return get_config(env_file)


@pytest.fixture(scope="session")
def discovery_document(test_config):
    """
    Session-scoped fixture providing cached discovery document.

    Fetches the discovery document once and caches it for all tests.
    Includes retry logic to handle transient rate limits.
    """

    @retry_with_backoff()
    def fetch_discovery():
        disco_doc_req = DiscoveryDocumentRequest(
            address=test_config["TEST_DISCO_ADDRESS"]
        )
        response = get_discovery_document(disco_doc_req)

        # If we got a 429, check the response and raise to trigger retry
        if not response.is_successful and "429" in str(response.error):
            request = httpx.Request("GET", test_config["TEST_DISCO_ADDRESS"])
            raise httpx.HTTPStatusError(
                RATE_LIMIT_ERROR_MESSAGE,
                request=request,
                response=httpx.Response(429),
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

    @retry_with_backoff()
    def fetch_jwks():
        jwks_req = JwksRequest(address=test_config["TEST_JWKS_ADDRESS"])
        response = get_jwks(jwks_req)

        # If we got a 429, check the response and raise to trigger retry
        if not response.is_successful and "429" in str(response.error):
            request = httpx.Request("GET", test_config["TEST_JWKS_ADDRESS"])
            raise httpx.HTTPStatusError(
                RATE_LIMIT_ERROR_MESSAGE,
                request=request,
                response=httpx.Response(429),
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
def userinfo_endpoint(discovery_document):
    """Provide the UserInfo endpoint from cached discovery document."""
    return discovery_document.userinfo_endpoint


@pytest.fixture(scope="session")
def client_credentials_token(test_config, token_endpoint):
    """
    Session-scoped fixture providing a cached client credentials token.

    Generates one token per test session and shares it across all tests.
    Includes retry logic to handle transient rate limits.
    """

    @retry_with_backoff()
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
                RATE_LIMIT_ERROR_MESSAGE,
                request=request,
                response=httpx.Response(429),
            )

        return response

    return fetch_token()


@pytest.fixture(scope="session", autouse=True)
def cleanup_http_client():
    """
    Session-scoped fixture that ensures HTTP client is properly closed.

    This fixture automatically runs after all tests complete to close
    the persistent HTTP client and prevent resource warnings about
    unclosed SSL sockets.

    Each pytest-xdist worker process has its own HTTP client cache,
    so cleanup happens independently per worker without race conditions.
    """
    yield
    # Cleanup happens after all tests in the session
    # Ignore errors during cleanup (e.g., if client was never created)
    with suppress(Exception):
        close_http_client()
