import time
from typing import List

from jose import jwk
from jose import jwt as jwt_utils
from jose.utils import base64url_decode

from .discovery import get_discovery_document, DiscoveryDocumentRequest
from .exceptions import PyOidcException
from .jwks import get_jwks, JwksRequest, JsonWebKey


def get_public_key(jwt: str, keys: List[JsonWebKey]) -> JsonWebKey:
    headers = jwt_utils.get_unverified_headers(jwt)
    key = list(filter(lambda x: x.kid == headers["kid"], keys))
    if not key:
        raise PyOidcException("No matching kid found")

    return key[0]


# TODO: Validate issuer, audience, etc.
def validate_token(jwt: str, disco_doc_address: str) -> dict:
    disco_doc_response = get_discovery_document(
        DiscoveryDocumentRequest(address=disco_doc_address)
    )
    if not disco_doc_response.is_successful:
        raise PyOidcException(disco_doc_response.error)

    jwks_response = get_jwks(JwksRequest(address=disco_doc_response.jwks_uri))
    if not jwks_response.is_successful:
        raise PyOidcException(jwks_response.error)

    # TODO: refactor this
    message, encoded_signature = str(jwt).rsplit(".", 1)

    decoded_signature = base64url_decode(encoded_signature.encode("utf-8"))

    # TODO: find a better way to handle not passing an alg - Azure issue
    key = get_public_key(jwt, jwks_response.keys).as_dict()
    if not key.get("alg"):
        key["alg"] = "RS256"

    json_web_key = jwk.construct(key)

    if not json_web_key.verify(message.encode("utf-8"), decoded_signature):
        raise PyOidcException("Invalid signature.")

    claims = jwt_utils.get_unverified_claims(jwt)

    if claims["exp"] < time.time():
        raise PyOidcException("Expired token.")

    return claims


__all__ = ["validate_token"]
