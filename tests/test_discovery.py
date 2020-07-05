from py_identity_model import DiscoveryDocumentRequest, get_discovery_document
from .test_utils import get_config

TEST_DISCO_ADDRESS = get_config()["TEST_DISCO_ADDRESS"]


def test_get_discovery_document_is_successful():
    disco_doc_request = DiscoveryDocumentRequest(address=TEST_DISCO_ADDRESS)
    disco_doc_response = get_discovery_document(disco_doc_request)
    assert disco_doc_response.is_successful
    assert disco_doc_response.issuer
    assert disco_doc_response.jwks_uri
    assert disco_doc_response.token_endpoint
    assert disco_doc_response.authorization_endpoint


# def test_get_discovery_document_fails():
#     disco_doc_request = DiscoveryDocumentRequest(address='http://not.a.real.address')
#     disco_doc_response = get_discovery_document(disco_doc_request)
#     assert disco_doc_response.is_successful is False
