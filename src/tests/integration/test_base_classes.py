"""Integration tests for base request/response classes."""

import pytest

from py_identity_model import (
    BaseResponse,
)


@pytest.mark.integration
class TestBaseClassesIntegration:
    """Test base classes work with real identity provider responses."""

    def test_discovery_response_is_base_response(self, discovery_document):
        assert isinstance(discovery_document, BaseResponse)
        assert discovery_document.is_successful is True

    def test_base_response_polymorphism(self, discovery_document):
        """Can treat any response as BaseResponse."""
        resp: BaseResponse = discovery_document
        assert resp.is_successful is True
