import httpx
import respx

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
    @respx.mock
    def test_get_discovery_document_success(self):
        # Mock successful response
        url = "https://example.com/.well-known/openid_configuration"
        respx.get(url).mock(
            return_value=httpx.Response(
                200,
                json={
                    "issuer": "https://example.com",
                    "jwks_uri": "https://example.com/jwks",
                    "authorization_endpoint": "https://example.com/auth",
                    "token_endpoint": "https://example.com/token",
                    "response_types_supported": ["code", "id_token"],
                    "subject_types_supported": ["public"],
                    "id_token_signing_alg_values_supported": ["RS256"],
                },
                headers={"Content-Type": "application/json"},
            )
        )

        request = DiscoveryDocumentRequest(address=url)
        result = get_discovery_document(request)

        assert result.is_successful is True
        assert result.issuer == "https://example.com"
        assert result.jwks_uri == "https://example.com/jwks"
        assert result.authorization_endpoint == "https://example.com/auth"
        assert result.token_endpoint == "https://example.com/token"
        assert result.response_types_supported == ["code", "id_token"]
        assert result.subject_types_supported == ["public"]
        assert result.id_token_signing_alg_values_supported == ["RS256"]

    @respx.mock
    def test_get_discovery_document_http_error(self):
        # Mock HTTP error response
        url = "https://example.com/.well-known/openid_configuration"
        respx.get(url).mock(
            return_value=httpx.Response(404, content=b"Not Found")
        )

        request = DiscoveryDocumentRequest(address=url)
        result = get_discovery_document(request)

        assert result.is_successful is False
        assert result.error is not None
        assert "404" in result.error
        assert "Not Found" in result.error

    @respx.mock
    def test_get_discovery_document_wrong_content_type(self):
        # Mock response with wrong content type
        url = "https://example.com/.well-known/openid_configuration"
        respx.get(url).mock(
            return_value=httpx.Response(
                200,
                content=b"<html>Not JSON</html>",
                headers={"Content-Type": "text/html"},
            )
        )

        request = DiscoveryDocumentRequest(address=url)
        result = get_discovery_document(request)

        assert result.is_successful is False
        assert result.error is not None
        assert "Invalid content type" in result.error

    @respx.mock
    def test_get_discovery_document_partial_json_response(self):
        # Mock response with partial JSON data
        url = "https://example.com/.well-known/openid_configuration"
        respx.get(url).mock(
            return_value=httpx.Response(
                200,
                json={
                    "issuer": "https://example.com",
                    "jwks_uri": "https://example.com/jwks",
                    # Missing some required/optional fields
                },
                headers={"Content-Type": "application/json"},
            )
        )

        request = DiscoveryDocumentRequest(address=url)
        result = get_discovery_document(request)

        assert result.is_successful is False
        assert result.error is not None
        assert "Missing required parameters" in result.error
