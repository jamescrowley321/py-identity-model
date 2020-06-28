from dataclasses import dataclass
from typing import Optional

import requests


@dataclass
class DiscoveryDocumentRequest:
    address: str


# TODO: full disco doc support
@dataclass
class DiscoveryDocumentResponse:
    is_successful: bool
    issuer: Optional[str] = None
    jwks_uri: Optional[str] = None
    authorization_endpoint: Optional[str] = None
    token_endpoint: Optional[str] = None
    error: Optional[str] = None


def get_discovery_document(
    disco_doc_req: DiscoveryDocumentRequest,
) -> DiscoveryDocumentResponse:
    response = requests.get(disco_doc_req.address)
    # TODO: raise for status and handle exceptions
    if response.ok:
        response_json = response.json()
        return DiscoveryDocumentResponse(
            issuer=response_json["issuer"],
            jwks_uri=response_json["jwks_uri"],
            authorization_endpoint=response_json["authorization_endpoint"],
            token_endpoint=response_json["token_endpoint"],
            is_successful=True,
        )
    else:
        return DiscoveryDocumentResponse(
            is_successful=False,
            error=f"Discovery document request failed with status code: "
            f"{response.status_code}. Response Content: {response.content}",
        )


__all__ = [
    "DiscoveryDocumentRequest",
    "DiscoveryDocumentResponse",
    "get_discovery_document",
]
