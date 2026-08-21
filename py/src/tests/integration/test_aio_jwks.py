"""Async integration tests for JWKS fetching."""

import pytest

from py_identity_model import JsonWebKey
from py_identity_model.aio.jwks import get_jwks
from py_identity_model.core.models import JwksRequest
from py_identity_model.exceptions import FailedResponseAccessError


@pytest.mark.integration
class TestAsyncJWKS:
    """Async counterparts of sync JWKS integration tests."""

    async def test_get_jwks_success(self, test_config):
        """Fetch JWKS via async API and validate key fields."""
        request = JwksRequest(address=test_config["TEST_JWKS_ADDRESS"])
        response = await get_jwks(request)

        assert response.is_successful is True
        assert response.keys is not None
        assert len(response.keys) > 0

        for key in response.keys:
            assert isinstance(key, JsonWebKey)
            assert key.kty is not None
            assert key.alg is not None
            assert key.use is not None
            assert key.kid is not None

            if key.kty == "RSA":
                assert key.n is not None
                assert key.e is not None
            elif key.kty == "EC":
                assert key.crv is not None
                assert key.x is not None
                assert key.y is not None

    async def test_get_jwks_failure(self):
        """Non-JWKS URL returns unsuccessful response."""
        request = JwksRequest(address="https://google.com")
        response = await get_jwks(request)

        assert response.is_successful is False
        assert response.error is not None
        with pytest.raises(FailedResponseAccessError):
            _ = response.keys

    async def test_get_jwks_network_error(self):
        """Malformed URL returns unsuccessful response with error detail."""
        request = JwksRequest(address="not-a-valid-url")
        response = await get_jwks(request)

        assert response.is_successful is False
        assert response.error is not None
        with pytest.raises(FailedResponseAccessError):
            _ = response.keys

    async def test_async_sync_parity(self, jwks_response, test_config):
        """Async JWKS keys match session-scoped sync JWKS keys."""
        request = JwksRequest(address=test_config["TEST_JWKS_ADDRESS"])
        async_response = await get_jwks(request)

        assert async_response.is_successful is True
        assert async_response.keys is not None
        assert jwks_response.keys is not None

        sync_kids = {k.kid for k in jwks_response.keys}
        async_kids = {k.kid for k in async_response.keys}
        assert sync_kids == async_kids
