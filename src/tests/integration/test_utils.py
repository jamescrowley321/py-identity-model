import os
from pathlib import Path

from dotenv import load_dotenv


# Global variable to store the current env file path
_current_env_file: str | None = None


def set_env_file(env_file_path: str | None) -> None:
    """
    Set the environment file to use for configuration.

    Args:
        env_file_path: Path to the environment file, or None to use default
    """
    global _current_env_file
    _current_env_file = env_file_path

    if env_file_path and Path(env_file_path).is_file():
        # Load the specified env file only if it exists
        load_dotenv(env_file_path, override=True)
    elif Path(".env").is_file():
        # Load default .env file only if it exists
        # Don't load .env.local - it's for local IdentityServer testing only
        load_dotenv(".env", override=True)

    # Clear SSL certificate environment variables for external service testing
    # These may be set in .env.local for local IdentityServer testing but should
    # not be used when testing against external services like Ory.
    #
    # We clear them BEFORE clearing caches to ensure get_ssl_verify() returns
    # the correct value (True for system certificates) on next call.
    os.environ.pop("SSL_CERT_FILE", None)
    os.environ.pop("REQUESTS_CA_BUNDLE", None)
    os.environ.pop("CURL_CA_BUNDLE", None)

    # Clear all SSL and HTTP client caches to pick up environment changes.
    # This is safe in parallel execution because each worker has its own process
    # and environment, and this only runs once per session during fixture initialization.
    from py_identity_model.aio.http_client import _reset_async_http_client
    from py_identity_model.ssl_config import get_ssl_verify
    from py_identity_model.sync.http_client import _reset_http_client

    get_ssl_verify.cache_clear()
    _reset_http_client()
    _reset_async_http_client()


def get_alternate_provider_expired_token() -> str | None:
    """
    Get an expired token from an alternate provider for cross-provider testing.

    Loads the expired token from .env.local which can be used to test that
    tokens from one provider fail validation against another provider's
    discovery endpoint.

    Returns:
        The expired token string, or None if .env.local doesn't exist
    """
    env_local_path = Path(".env.local")
    if not env_local_path.is_file():
        return None

    # Temporarily load .env.local to get the token without affecting current env
    from dotenv import dotenv_values

    local_config = dotenv_values(env_local_path)
    return local_config.get("TEST_EXPIRED_TOKEN")


def get_config(env_file: str | None = None) -> dict:
    """
    Get test configuration from environment variables.

    Args:
        env_file: Optional path to environment file. If provided, will load
                 this file before returning configuration.

    Returns:
        Dictionary containing test configuration
    """
    # If env_file parameter is provided, use it
    if env_file is not None:
        set_env_file(env_file)

    return {
        "TEST_DISCO_ADDRESS": os.environ.get("TEST_DISCO_ADDRESS", ""),
        "TEST_JWKS_ADDRESS": os.environ.get("TEST_JWKS_ADDRESS", ""),
        "TEST_CLIENT_ID": os.environ.get("TEST_CLIENT_ID", ""),
        "TEST_CLIENT_SECRET": os.environ.get("TEST_CLIENT_SECRET", ""),
        "TEST_SCOPE": os.environ.get("TEST_SCOPE", ""),
        "TEST_EXPIRED_TOKEN": os.environ.get("TEST_EXPIRED_TOKEN", ""),
        "TEST_AUDIENCE": os.environ.get("TEST_AUDIENCE", ""),
    }
