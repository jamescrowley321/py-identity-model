import time
from typing import List

from jose import jwk
from jose import jwt as jwt_utils
from jose.utils import base64url_decode

from .discovery import get_discovery_document, DiscoveryDocumentRequest
from .exceptions import PyIdentityModelException
from .jwks import get_jwks, JwksRequest, JsonWebKey


def get_public_key(jwt: str, keys: List[JsonWebKey]) -> JsonWebKey:
    headers = jwt_utils.get_unverified_headers(jwt)
    keys = list(filter(lambda x: x.kid == headers["kid"], keys))
    if not keys:
        raise PyIdentityModelException("No matching kid found")

    key = keys[0]
    if not key.alg:
        key.alg = headers["alg"]

    return key


# TODO: Validate issuer, audience, etc.
def validate_token(jwt: str, disco_doc_address: str) -> dict:
    disco_doc_response = get_discovery_document(
        DiscoveryDocumentRequest(address=disco_doc_address)
    )
    if not disco_doc_response.is_successful:
        raise PyIdentityModelException(disco_doc_response.error)

    jwks_response = get_jwks(JwksRequest(address=disco_doc_response.jwks_uri))
    if not jwks_response.is_successful:
        raise PyIdentityModelException(jwks_response.error)

    # TODO: refactor this
    message, encoded_signature = str(jwt).rsplit(".", 1)

    decoded_signature = base64url_decode(encoded_signature.encode("utf-8"))

    key = get_public_key(jwt, jwks_response.keys).as_dict()
    json_web_key = jwk.construct(key)

    if not json_web_key.verify(message.encode("utf-8"), decoded_signature):
        raise PyIdentityModelException("Invalid signature.")

    claims = jwt_utils.get_unverified_claims(jwt)

    if claims["exp"] < time.time():
        raise PyIdentityModelException("Expired token.")

    return claims


__all__ = ["validate_token"]
