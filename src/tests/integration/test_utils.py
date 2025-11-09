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
    # These are set for local IdentityServer testing and should not be used
    # when testing against external services like Ory
    os.environ.pop("SSL_CERT_FILE", None)
    os.environ.pop("REQUESTS_CA_BUNDLE", None)
    os.environ.pop("CURL_CA_BUNDLE", None)

    # Clear the SSL verify cache to pick up the environment changes
    from py_identity_model.ssl_config import get_ssl_verify

    get_ssl_verify.cache_clear()


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
