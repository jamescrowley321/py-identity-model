from py_identity_model import (
    DiscoveryDocumentRequest,
    get_discovery_document,
)


def test_get_discovery_document_is_successful(discovery_document):
    """Test using cached discovery document to avoid rate limits."""
    assert discovery_document.is_successful
    assert discovery_document.issuer
    assert discovery_document.jwks_uri
    assert discovery_document.token_endpoint
    assert discovery_document.authorization_endpoint


def test_get_discovery_document_fails(env_file):
    disco_doc_request = DiscoveryDocumentRequest(address="https://google.com")
    disco_doc_response = get_discovery_document(disco_doc_request)
    assert disco_doc_response.is_successful is False
