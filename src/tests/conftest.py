import pytest
from typing import Optional


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
    config.addinivalue_line("markers", "integration: mark test as an integration test")

    # Store env file option in config for access by other modules
    env_file = config.getoption("--env-file")
    if env_file:
        config._env_file = env_file


@pytest.fixture(scope="session")
def env_file(request) -> Optional[str]:
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
    yield
    # Cleanup code can go here if needed
