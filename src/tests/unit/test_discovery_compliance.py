from unittest.mock import Mock, patch

import pytest
import requests

from py_identity_model.discovery import (
    DiscoveryDocumentRequest,
    _validate_https_url,
    _validate_issuer,
    _validate_parameter_values,
    _validate_required_parameters,
    get_discovery_document,
)
from py_identity_model.exceptions import (
    ConfigurationException,
    DiscoveryException,
)


class TestDiscoveryValidationFunctions:
    """Test the new validation functions for Discovery compliance"""

    def test_validate_issuer_valid_https(self):
        """Test that valid HTTPS issuers pass validation"""
        valid_issuers = [
            "https://example.com",
            "https://auth.example.com",
            "https://example.com/auth",
            "https://example.com:8443",
        ]
        for issuer in valid_issuers:
            _validate_issuer(issuer)  # Should not raise

    def test_validate_issuer_invalid_scheme(self):
        """Test that non-HTTPS issuers fail validation"""
        invalid_issuers = [
            "http://example.com",
            "ftp://example.com",
            "ws://example.com",
        ]
        for issuer in invalid_issuers:
            with pytest.raises(
                ConfigurationException,
                match="must use HTTPS scheme",
            ):
                _validate_issuer(issuer)

    def test_validate_issuer_with_query_fragment(self):
        """Test that issuers with query or fragment components fail validation"""
        with pytest.raises(
            ConfigurationException,
            match="must not contain query or fragment",
        ):
            _validate_issuer("https://example.com?query=param")

        with pytest.raises(
            ConfigurationException,
            match="must not contain query or fragment",
        ):
            _validate_issuer("https://example.com#fragment")

    def test_validate_issuer_empty_or_invalid(self):
        """Test that empty or invalid issuers fail validation"""
        with pytest.raises(ConfigurationException, match="required"):
            _validate_issuer("")

        with pytest.raises(
            ConfigurationException,
            match="valid URL with host",
        ):
            _validate_issuer("https://")

    def test_validate_https_url_valid_urls(self):
        """Test that valid URLs pass validation"""
        valid_urls = [
            "https://example.com/path",
            "http://localhost:8080",  # Allow http for development
            "https://api.example.com:443/endpoint",
        ]
        for url in valid_urls:
            _validate_https_url(url, "test_param")  # Should not raise

    def test_validate_https_url_empty_allowed(self):
        """Test that empty URLs are allowed (optional parameters)"""
        _validate_https_url("", "test_param")  # Should not raise
        _validate_https_url(None, "test_param")  # type: ignore # Should not raise

    def test_validate_https_url_invalid_urls(self):
        """Test that invalid URLs fail validation"""
        invalid_urls = [
            "ftp://example.com",
            "not-a-url",
            "relative/path",
            "ws://example.com",
        ]
        for url in invalid_urls:
            with pytest.raises(
                ConfigurationException,
                match="must be a valid HTTP/HTTPS URL",
            ):
                _validate_https_url(url, "test_param")

    def test_validate_required_parameters_all_present(self):
        """Test that validation passes when all required parameters are present"""
        valid_data = {
            "issuer": "https://example.com",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }
        _validate_required_parameters(valid_data)  # Should not raise

    def test_validate_required_parameters_missing(self):
        """Test that validation fails when required parameters are missing"""
        # Missing issuer
        with pytest.raises(
            DiscoveryException,
            match=r"Missing required parameters.*issuer",
        ):
            _validate_required_parameters(
                {
                    "response_types_supported": ["code"],
                    "subject_types_supported": ["public"],
                    "id_token_signing_alg_values_supported": ["RS256"],
                },
            )

        # Missing multiple parameters
        with pytest.raises(
            DiscoveryException,
            match="Missing required parameters",
        ):
            _validate_required_parameters({"issuer": "https://example.com"})

    def test_validate_parameter_values_valid_subject_types(self):
        """Test that valid subject types pass validation"""
        valid_data = {
            "subject_types_supported": ["public"],
        }
        _validate_parameter_values(valid_data)  # Should not raise

        valid_data = {
            "subject_types_supported": ["public", "pairwise"],
        }
        _validate_parameter_values(valid_data)  # Should not raise

    def test_validate_parameter_values_invalid_subject_types(self):
        """Test that invalid subject types fail validation"""
        with pytest.raises(
            DiscoveryException,
            match=r"Invalid subject type.*Must be 'public' or 'pairwise'",
        ):
            _validate_parameter_values(
                {
                    "subject_types_supported": ["invalid_type"],
                },
            )

    def test_validate_parameter_values_valid_response_types(self):
        """Test that valid response types pass validation"""
        valid_response_types = [
            ["code"],
            ["id_token"],
            ["code", "id_token"],
            ["code id_token token"],
        ]
        for response_types in valid_response_types:
            _validate_parameter_values(
                {
                    "response_types_supported": response_types,
                },
            )  # Should not raise

    def test_validate_parameter_values_invalid_response_types(self):
        """Test that invalid response types fail validation"""
        with pytest.raises(DiscoveryException, match="Invalid response type"):
            _validate_parameter_values(
                {
                    "response_types_supported": ["invalid_response_type"],
                },
            )


class TestDiscoveryComplianceIntegration:
    """Test the integrated compliance validation in get_discovery_document"""

    @patch("py_identity_model.discovery.requests.get")
    def test_discovery_validates_required_parameters(self, mock_get):
        """Test that discovery document validation catches missing required parameters"""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.headers = {"Content-Type": "application/json"}
        mock_response.json.return_value = {
            "issuer": "https://example.com",
            "jwks_uri": "https://example.com/jwks",
            # Missing required parameters
        }
        mock_get.return_value = mock_response

        request = DiscoveryDocumentRequest(
            address="https://example.com/.well-known/openid_configuration",
        )
        result = get_discovery_document(request)

        assert result.is_successful is False
        assert result.error is not None
        assert "Missing required parameters" in result.error

    @patch("py_identity_model.discovery.requests.get")
    def test_discovery_validates_issuer_format(self, mock_get):
        """Test that discovery document validation catches invalid issuer format"""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.headers = {"Content-Type": "application/json"}
        mock_response.json.return_value = {
            "issuer": "http://example.com?query=param",  # Invalid issuer
            "jwks_uri": "https://example.com/jwks",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }
        mock_get.return_value = mock_response

        request = DiscoveryDocumentRequest(
            address="https://example.com/.well-known/openid_configuration",
        )
        result = get_discovery_document(request)

        assert result.is_successful is False
        assert result.error is not None
        assert "Invalid issuer" in result.error

    @patch("py_identity_model.discovery.requests.get")
    def test_discovery_validates_parameter_values(self, mock_get):
        """Test that discovery document validation catches invalid parameter values"""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.headers = {"Content-Type": "application/json"}
        mock_response.json.return_value = {
            "issuer": "https://example.com",
            "jwks_uri": "https://example.com/jwks",
            "response_types_supported": ["code"],
            "subject_types_supported": ["invalid_subject_type"],  # Invalid
            "id_token_signing_alg_values_supported": ["RS256"],
        }
        mock_get.return_value = mock_response

        request = DiscoveryDocumentRequest(
            address="https://example.com/.well-known/openid_configuration",
        )
        result = get_discovery_document(request)

        assert result.is_successful is False
        assert result.error is not None
        assert "Invalid parameter values" in result.error

    @patch("py_identity_model.discovery.requests.get")
    def test_discovery_validates_endpoint_urls(self, mock_get):
        """Test that discovery document validation catches invalid endpoint URLs"""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.headers = {"Content-Type": "application/json"}
        mock_response.json.return_value = {
            "issuer": "https://example.com",
            "jwks_uri": "not-a-valid-url",  # Invalid URL
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }
        mock_get.return_value = mock_response

        request = DiscoveryDocumentRequest(
            address="https://example.com/.well-known/openid_configuration",
        )
        result = get_discovery_document(request)

        assert result.is_successful is False
        assert result.error is not None
        assert "Invalid endpoint URL" in result.error

    @patch("py_identity_model.discovery.requests.get")
    def test_discovery_handles_network_errors(self, mock_get):
        """Test that discovery document handles network errors properly"""
        mock_get.side_effect = requests.exceptions.ConnectionError(
            "Network error",
        )

        request = DiscoveryDocumentRequest(
            address="https://example.com/.well-known/openid_configuration",
        )
        result = get_discovery_document(request)

        assert result.is_successful is False
        assert result.error is not None
        assert (
            "Network error during discovery document request" in result.error
        )

    @patch("py_identity_model.discovery.requests.get")
    def test_discovery_handles_invalid_json(self, mock_get):
        """Test that discovery document handles invalid JSON responses"""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.headers = {"Content-Type": "application/json"}
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_get.return_value = mock_response

        request = DiscoveryDocumentRequest(
            address="https://example.com/.well-known/openid_configuration",
        )
        result = get_discovery_document(request)

        assert result.is_successful is False
        assert result.error is not None
        assert "Invalid JSON response" in result.error

    @patch("py_identity_model.discovery.requests.get")
    def test_discovery_validates_content_type(self, mock_get):
        """Test that discovery document validates content type"""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.headers = {"Content-Type": "text/html"}
        mock_get.return_value = mock_response

        request = DiscoveryDocumentRequest(
            address="https://example.com/.well-known/openid_configuration",
        )
        result = get_discovery_document(request)

        assert result.is_successful is False
        assert result.error is not None
        assert "Invalid content type" in result.error

    @patch("py_identity_model.discovery.requests.get")
    def test_discovery_success_with_valid_data(self, mock_get):
        """Test that discovery document succeeds with valid, compliant data"""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.headers = {"Content-Type": "application/json"}
        mock_response.json.return_value = {
            "issuer": "https://example.com",
            "jwks_uri": "https://example.com/jwks",
            "authorization_endpoint": "https://example.com/auth",
            "token_endpoint": "https://example.com/token",
            "response_types_supported": ["code", "id_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256", "HS256"],
        }
        mock_get.return_value = mock_response

        request = DiscoveryDocumentRequest(
            address="https://example.com/.well-known/openid_configuration",
        )
        result = get_discovery_document(request)

        assert result.is_successful is True
        assert result.issuer == "https://example.com"
        assert result.jwks_uri == "https://example.com/jwks"
        assert result.response_types_supported == ["code", "id_token"]
        assert result.subject_types_supported == ["public"]
        assert result.id_token_signing_alg_values_supported == [
            "RS256",
            "HS256",
        ]
