import os
from typing import Optional

from dotenv import load_dotenv

# Global variable to store the current env file path
_current_env_file: Optional[str] = None


def set_env_file(env_file_path: Optional[str]) -> None:
    """
    Set the environment file to use for configuration.

    Args:
        env_file_path: Path to the environment file, or None to use default
    """
    global _current_env_file
    _current_env_file = env_file_path

    if env_file_path and os.path.isfile(env_file_path):
        # Load the specified env file only if it exists
        load_dotenv(env_file_path, override=True)
    elif os.path.isfile(".env"):
        # Load default .env file only if it exists
        load_dotenv()


def get_config(env_file: Optional[str] = None) -> dict:
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
