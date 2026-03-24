"""Integration tests for base request/response classes."""

import pytest

from py_identity_model import (
    BaseRequest,
    BaseResponse,
    DiscoveryDocumentRequest,
)


@pytest.mark.integration
class TestBaseClassesIntegration:
    """Test base classes work with real identity provider responses."""

    def test_discovery_request_is_base_request(self, test_config):
        req = DiscoveryDocumentRequest(
            address=test_config["TEST_DISCO_ADDRESS"]
        )
        assert isinstance(req, BaseRequest)

    def test_discovery_response_is_base_response(self, discovery_document):
        assert isinstance(discovery_document, BaseResponse)
        assert discovery_document.is_successful is True

    def test_base_response_polymorphism(self, discovery_document):
        """Can treat any response as BaseResponse."""
        resp: BaseResponse = discovery_document
        assert resp.is_successful is True
