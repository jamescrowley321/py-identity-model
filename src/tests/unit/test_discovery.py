from unittest.mock import Mock, patch
from py_identity_model.discovery import (
    DiscoveryDocumentRequest,
    DiscoveryDocumentResponse,
    get_discovery_document,
)


class TestDiscoveryDocumentRequest:
    def test_discovery_document_request_creation(self):
        address = "https://example.com/.well-known/openid_configuration"
        request = DiscoveryDocumentRequest(address=address)
        assert request.address == address


class TestDiscoveryDocumentResponse:
    def test_discovery_document_response_creation_minimal(self):
        response = DiscoveryDocumentResponse(is_successful=True)
        assert response.is_successful is True
        assert response.issuer is None
        assert response.jwks_uri is None

    def test_discovery_document_response_creation_full(self):
        response = DiscoveryDocumentResponse(
            is_successful=True,
            issuer="https://example.com",
            jwks_uri="https://example.com/jwks",
            authorization_endpoint="https://example.com/auth",
            token_endpoint="https://example.com/token",
        )
        assert response.is_successful is True
        assert response.issuer == "https://example.com"
        assert response.jwks_uri == "https://example.com/jwks"
        assert response.authorization_endpoint == "https://example.com/auth"
        assert response.token_endpoint == "https://example.com/token"


class TestGetDiscoveryDocument:
    @patch("py_identity_model.discovery.requests.get")
    def test_get_discovery_document_success(self, mock_get):
        # Mock successful response
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
            "id_token_signing_alg_values_supported": ["RS256"],
        }
        mock_get.return_value = mock_response

        request = DiscoveryDocumentRequest(
            address="https://example.com/.well-known/openid_configuration"
        )
        result = get_discovery_document(request)

        assert result.is_successful is True
        assert result.issuer == "https://example.com"
        assert result.jwks_uri == "https://example.com/jwks"
        assert result.authorization_endpoint == "https://example.com/auth"
        assert result.token_endpoint == "https://example.com/token"
        assert result.response_types_supported == ["code", "id_token"]
        assert result.subject_types_supported == ["public"]
        assert result.id_token_signing_alg_values_supported == ["RS256"]
        mock_get.assert_called_once_with(
            "https://example.com/.well-known/openid_configuration", timeout=30
        )

    @patch("py_identity_model.discovery.requests.get")
    def test_get_discovery_document_http_error(self, mock_get):
        # Mock HTTP error response
        mock_response = Mock()
        mock_response.ok = False
        mock_response.status_code = 404
        mock_response.content = b"Not Found"
        mock_get.return_value = mock_response

        request = DiscoveryDocumentRequest(
            address="https://example.com/.well-known/openid_configuration"
        )
        result = get_discovery_document(request)

        assert result.is_successful is False
        assert "404" in result.error
        assert "Not Found" in result.error
        mock_get.assert_called_once_with(
            "https://example.com/.well-known/openid_configuration", timeout=30
        )

    @patch("py_identity_model.discovery.requests.get")
    def test_get_discovery_document_wrong_content_type(self, mock_get):
        # Mock response with wrong content type
        mock_response = Mock()
        mock_response.ok = True
        mock_response.headers = {"Content-Type": "text/html"}
        mock_response.status_code = 200
        mock_response.content = b"<html>Not JSON</html>"
        mock_get.return_value = mock_response

        request = DiscoveryDocumentRequest(
            address="https://example.com/.well-known/openid_configuration"
        )
        result = get_discovery_document(request)

        assert result.is_successful is False
        assert "Invalid content type" in result.error
        mock_get.assert_called_once_with(
            "https://example.com/.well-known/openid_configuration", timeout=30
        )

    @patch("py_identity_model.discovery.requests.get")
    def test_get_discovery_document_partial_json_response(self, mock_get):
        # Mock response with partial JSON data
        mock_response = Mock()
        mock_response.ok = True
        mock_response.headers = {"Content-Type": "application/json"}
        mock_response.json.return_value = {
            "issuer": "https://example.com",
            "jwks_uri": "https://example.com/jwks",
            # Missing some required/optional fields
        }
        mock_get.return_value = mock_response

        request = DiscoveryDocumentRequest(
            address="https://example.com/.well-known/openid_configuration"
        )
        result = get_discovery_document(request)

        assert result.is_successful is False
        assert "Missing required parameters" in result.error
        mock_get.assert_called_once_with(
            "https://example.com/.well-known/openid_configuration", timeout=30
        )
