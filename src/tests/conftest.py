import pytest


def pytest_addoption(parser):
    """Add command line options for test configuration."""
    parser.addoption(
        "--env-file",
        action="store",
        default=None,
        help="Path to environment file to load for tests",
    )


def pytest_configure(config):
    """Configure pytest based on command line options."""
    # Add custom markers for test categorization
    config.addinivalue_line("markers", "unit: mark test as a unit test")
    config.addinivalue_line(
        "markers",
        "integration: mark test as an integration test",
    )

    # Store env file option in config for access by other modules
    env_file = config.getoption("--env-file")
    if env_file:
        config._env_file = env_file
    else:
        # Default to .env if no env file specified
        config._env_file = ".env"


@pytest.fixture(scope="session")
def env_file(request) -> str | None:
    """Fixture to provide the env file path to tests."""
    return getattr(request.config, "_env_file", None)


def pytest_collection_modifyitems(config, items):
    """Automatically mark tests based on their location."""
    for item in items:
        # Get the path relative to the tests directory
        test_path = str(item.fspath.relto(item.config.rootdir))

        if "tests/unit" in test_path:
            item.add_marker(pytest.mark.unit)
        elif "tests/integration" in test_path:
            item.add_marker(pytest.mark.integration)


# Session-scoped fixture to ensure proper test isolation
@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    """Setup test environment before running tests."""
    # This fixture runs automatically for all tests
    # Can be used for global setup/teardown if needed
    # Cleanup code can go here if needed


@pytest.fixture(autouse=True)
def _clear_async_caches():
    """Clear async LRU caches between tests.

    async-lru >= 2.2.0 enforces single event loop per cache instance.
    Since pytest-asyncio creates a new event loop per test function,
    stale caches from a previous loop cause RuntimeError. Clearing
    them and resetting the loop binding before each test prevents this.
    """
    from py_identity_model.aio.token_validation import (
        _get_disco_response,
        _get_jwks_response,
        _get_public_key_by_kid,
    )

    for cache_fn in (
        _get_disco_response,
        _get_jwks_response,
        _get_public_key_by_kid,
    ):
        cache_fn.cache_clear()
        # Reset event loop binding added in async-lru 2.2.0
        loop_attr = "_LRUCacheWrapper__first_loop"
        if hasattr(cache_fn, loop_attr):
            setattr(cache_fn, loop_attr, None)

    # Reset the singleton async HTTP client so it gets recreated
    # on the new event loop
    from py_identity_model.aio.http_client import _reset_async_http_client

    _reset_async_http_client()
