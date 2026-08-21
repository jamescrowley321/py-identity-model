"""Tests for core error handlers."""

import httpx

from py_identity_model.core.error_handlers import (
    handle_discovery_error,
    handle_jwks_error,
    handle_token_error,
)
from py_identity_model.exceptions import (
    ConfigurationException,
    DiscoveryException,
)


class TestHandleDiscoveryError:
    """Tests for handle_discovery_error function."""

    def test_configuration_exception_with_issuer(self):
        """Test handling ConfigurationException with issuer in message."""
        exc = ConfigurationException("Invalid issuer format")
        result = handle_discovery_error(exc)

        assert result.is_successful is False
        assert result.error is not None
        assert "Invalid issuer" in result.error

    def test_configuration_exception_with_url(self):
        """Test handling ConfigurationException with URL in message."""
        exc = ConfigurationException("Invalid URL format")
        result = handle_discovery_error(exc)

        assert result.is_successful is False
        assert result.error is not None
        assert "Invalid endpoint URL" in result.error

    def test_configuration_exception_generic(self):
        """Test handling ConfigurationException without issuer/url keywords."""
        exc = ConfigurationException("Some other configuration error")
        result = handle_discovery_error(exc)

        assert result.is_successful is False
        assert result.error is not None
        assert "Some other configuration error" in result.error

    def test_discovery_exception_with_parameter(self):
        """Test handling DiscoveryException with parameter in message."""
        exc = DiscoveryException("Missing required parameter: issuer")
        result = handle_discovery_error(exc)

        assert result.is_successful is False
        assert result.error is not None
        assert "Missing required parameters" in result.error

    def test_discovery_exception_with_subject(self):
        """Test handling DiscoveryException with subject in message."""
        exc = DiscoveryException("Invalid subject_types_supported value")
        result = handle_discovery_error(exc)

        assert result.is_successful is False
        assert result.error is not None
        assert "Invalid parameter values" in result.error

    def test_discovery_exception_with_response_type(self):
        """Test handling DiscoveryException with response_type in message."""
        exc = DiscoveryException("Invalid response_types_supported")
        result = handle_discovery_error(exc)

        assert result.is_successful is False
        assert result.error is not None
        assert "Invalid parameter values" in result.error

    def test_discovery_exception_generic(self):
        """Test handling DiscoveryException without special keywords."""
        exc = DiscoveryException("Some discovery error")
        result = handle_discovery_error(exc)

        assert result.is_successful is False
        assert result.error is not None
        assert "Some discovery error" in result.error

    def test_request_error(self):
        """Test handling httpx.RequestError."""
        exc = httpx.RequestError("Connection failed")
        result = handle_discovery_error(exc)

        assert result.is_successful is False
        assert result.error is not None
        assert "Network error" in result.error

    def test_unexpected_error(self):
        """Test handling unexpected exception types."""
        exc = ValueError("Unexpected error")
        result = handle_discovery_error(exc)

        assert result.is_successful is False
        assert result.error is not None
        assert "Unexpected error" in result.error


class TestHandleJwksError:
    """Tests for handle_jwks_error function."""

    def test_request_error(self):
        """Test handling httpx.RequestError."""
        exc = httpx.RequestError("Connection failed")
        result = handle_jwks_error(exc)

        assert result.is_successful is False
        assert result.error is not None
        assert "Network error" in result.error
        assert "JWKS" in result.error

    def test_unexpected_error(self):
        """Test handling unexpected exception types."""
        exc = KeyError("Unexpected error")
        result = handle_jwks_error(exc)

        assert result.is_successful is False
        assert result.error is not None
        assert "Unhandled exception" in result.error


class TestHandleTokenError:
    """Tests for handle_token_error function."""

    def test_request_error(self):
        """Test handling httpx.RequestError."""
        exc = httpx.RequestError("Connection failed")
        result = handle_token_error(exc)

        assert result.is_successful is False
        assert result.error is not None
        assert "Network error" in result.error
        assert "token" in result.error

    def test_unexpected_error(self):
        """Test handling unexpected exception types."""
        exc = RuntimeError("Unexpected error")
        result = handle_token_error(exc)

        assert result.is_successful is False
        assert result.error is not None
        assert "Unexpected error" in result.error
