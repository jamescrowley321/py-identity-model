"""Integration tests for HTTP client dependency injection."""

import pytest

from py_identity_model import (
    DiscoveryDocumentRequest,
    HTTPClient,
    JwksRequest,
    get_discovery_document,
    get_jwks,
)


@pytest.mark.integration
class TestSyncDIIntegration:
    """Test sync functions with injected client against real providers."""

    def test_discovery_with_injected_client(self, test_config):
        """Fetch real discovery document using injected client."""
        with HTTPClient() as client:
            response = get_discovery_document(
                DiscoveryDocumentRequest(
                    address=test_config["TEST_DISCO_ADDRESS"],
                    require_https=test_config.get("TEST_REQUIRE_HTTPS", True),
                ),
                http_client=client,
            )

        assert response.is_successful
        assert response.issuer is not None

    def test_shared_client_across_calls(self, test_config):
        """Share a single injected client across multiple calls."""
        with HTTPClient() as client:
            disco = get_discovery_document(
                DiscoveryDocumentRequest(
                    address=test_config["TEST_DISCO_ADDRESS"],
                    require_https=test_config.get("TEST_REQUIRE_HTTPS", True),
                ),
                http_client=client,
            )
            assert disco.is_successful

            jwks = get_jwks(
                JwksRequest(address=test_config["TEST_JWKS_ADDRESS"]),
                http_client=client,
            )
            assert jwks.is_successful

    def test_custom_timeout_client(self, test_config):
        """Use client with custom timeout."""
        with HTTPClient(timeout=60.0) as client:
            response = get_discovery_document(
                DiscoveryDocumentRequest(
                    address=test_config["TEST_DISCO_ADDRESS"],
                    require_https=test_config.get("TEST_REQUIRE_HTTPS", True),
                ),
                http_client=client,
            )

        assert response.is_successful
