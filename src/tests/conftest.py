import pytest

from py_identity_model.aio.http_client import (
    _reset_async_http_client,
    close_async_http_client,
)
from py_identity_model.aio.token_validation import (
    clear_discovery_cache,
    clear_jwks_cache,
)


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


def pytest_collection_modifyitems(config, items):  # noqa: ARG001  # pytest hook spec requires `config` parameter name
    """Automatically mark tests based on their location."""
    for item in items:
        # Get the path relative to the tests directory
        test_path = str(item.fspath.relto(item.config.rootdir))

        if "tests/unit" in test_path:
            item.add_marker(pytest.mark.unit)
        elif "tests/integration" in test_path:
            item.add_marker(pytest.mark.integration)


@pytest.fixture(autouse=True)
async def _close_async_http_client():
    """Close the async HTTP client while the event loop is still alive.

    ``_reset_async_http_client()`` only nullifies the singleton reference.
    If the client has open connections when the reference is dropped, the
    orphaned ``AsyncClient`` is garbage-collected with live sockets and
    Python 3.13's stricter ``__del__`` raises ``ResourceWarning``, which
    pytest surfaces as ``PytestUnraisableExceptionWarning``.

    This async fixture runs its teardown *before* pytest-asyncio destroys
    the event loop, so ``await aclose()`` succeeds.  By the time the next
    test's setup calls ``_reset_async_http_client()``, the client is
    already closed and the reference is None — no orphaning.
    """
    yield
    await close_async_http_client()


@pytest.fixture(autouse=True)
def _clear_async_caches():
    """Clear async caches between tests.

    Since pytest-asyncio creates a new event loop per test function,
    stale caches from a previous loop must be cleared.
    """
    # Clear TTL-based discovery cache
    clear_discovery_cache()

    # Clear dict-based JWKS TTL cache
    clear_jwks_cache()

    # Reset the singleton async HTTP client so it gets recreated
    # on the new event loop.  The client is already closed by the
    # _close_async_http_client fixture's teardown phase.
    _reset_async_http_client()
