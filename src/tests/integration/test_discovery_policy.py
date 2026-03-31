"""Integration tests for DiscoveryPolicy."""

import pytest

from py_identity_model import (
    DiscoveryDocumentRequest,
    DiscoveryEndpoint,
    DiscoveryPolicy,
)
from py_identity_model.aio import (
    DiscoveryEndpoint as AioDiscoveryEndpoint,
)
from py_identity_model.aio import (
    DiscoveryPolicy as AioDiscoveryPolicy,
)
from py_identity_model.aio import (
    parse_discovery_url as aio_parse_discovery_url,
)
from py_identity_model.core.discovery_policy import parse_discovery_url


# Expected count of additional endpoint base addresses
EXPECTED_ADDITIONAL_ADDRESS_COUNT = 2


@pytest.mark.integration
class TestDiscoveryPolicyIntegration:
    def test_request_with_default_policy(self):
        req = DiscoveryDocumentRequest(
            address="https://auth.example.com",
            policy=DiscoveryPolicy(),
        )
        assert req.policy is not None
        assert req.policy.require_https is True

    def test_request_with_dev_policy(self):
        policy = DiscoveryPolicy(
            require_https=False,
            validate_issuer=False,
        )
        req = DiscoveryDocumentRequest(
            address="http://localhost:8080",
            policy=policy,
        )
        assert req.policy is not None
        assert req.policy.require_https is False
        assert req.policy.validate_issuer is False

    def test_parse_and_use_endpoint(self):
        endpoint = parse_discovery_url("https://auth.example.com")
        assert isinstance(endpoint, DiscoveryEndpoint)
        assert endpoint.authority == "https://auth.example.com"
        assert endpoint.url.endswith("/.well-known/openid-configuration")

    def test_policy_with_additional_addresses(self):
        policy = DiscoveryPolicy(
            additional_endpoint_base_addresses=[
                "https://cdn.example.com",
                "https://backup.example.com",
            ]
        )
        assert (
            len(policy.additional_endpoint_base_addresses)
            == EXPECTED_ADDITIONAL_ADDRESS_COUNT
        )

    def test_top_level_import(self):
        assert DiscoveryPolicy is not None
        assert DiscoveryEndpoint is not None
        assert callable(parse_discovery_url)

    def test_aio_import(self):
        assert AioDiscoveryPolicy is not None
        assert AioDiscoveryEndpoint is not None
        assert callable(aio_parse_discovery_url)
