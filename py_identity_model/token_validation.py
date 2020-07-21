from dataclasses import dataclass
from functools import lru_cache
from typing import List, Optional, Callable

from jose import jwt as jwt_utils

from .discovery import (
    get_discovery_document,
    DiscoveryDocumentRequest,
    DiscoveryDocumentResponse,
)
from .exceptions import PyIdentityModelException
from .jwks import get_jwks, JwksRequest, JsonWebKey, JwksResponse


@dataclass
class TokenValidationConfig:
    perform_disco: bool
    key: Optional[dict] = None
    audience: Optional[str] = None
    algorithms: Optional[List[str]] = None
    issuer: Optional[List[str]] = None
    subject: Optional[str] = None
    options: Optional[dict] = None
    claims_validator: Optional[Callable] = None


def _get_public_key(jwt: str, keys: List[JsonWebKey]) -> JsonWebKey:
    headers = jwt_utils.get_unverified_headers(jwt)
    filtered_keys = list(filter(lambda x: x.kid == headers["kid"], keys))
    if not filtered_keys:
        raise PyIdentityModelException("No matching kid found")

    key = filtered_keys[0]
    if not key.alg:
        key.alg = headers["alg"]

    return key


def _validate_token_config(
    token_validation_config: TokenValidationConfig,
) -> bool:
    if token_validation_config.perform_disco:
        return True

    if (
        not token_validation_config.key
        and not token_validation_config.algorithms
    ):
        raise PyIdentityModelException(
            "TokenValidationConfig.key and TokenValidationConfig.algorithms are required if perform_disco is False"
        )


@lru_cache(maxsize=32)
def _get_disco_response(disco_doc_address: str) -> DiscoveryDocumentResponse:
    return get_discovery_document(
        DiscoveryDocumentRequest(address=disco_doc_address)
    )


@lru_cache(maxsize=32)
def _get_jwks_response(jwks_uri: str) -> JwksResponse:
    return get_jwks(JwksRequest(address=jwks_uri))


def validate_token(
    jwt: str,
    token_validation_config: TokenValidationConfig,
    disco_doc_address: str = None,
) -> dict:
    _validate_token_config(token_validation_config)

    if token_validation_config.perform_disco:
        disco_doc_response = _get_disco_response(disco_doc_address)

        if not disco_doc_response.is_successful:
            raise PyIdentityModelException(disco_doc_response.error)

        jwks_response = _get_jwks_response(disco_doc_response.jwks_uri)
        if not jwks_response.is_successful:
            raise PyIdentityModelException(jwks_response.error)

        token_validation_config.key = _get_public_key(
            jwt, jwks_response.keys
        ).as_dict()

    decoded_token = jwt_utils.decode(
        jwt,
        token_validation_config.key,
        audience=token_validation_config.audience,
        algorithms=token_validation_config.algorithms,
        issuer=token_validation_config.issuer,
        subject=token_validation_config.subject,
        options=token_validation_config.options,
    )

    if token_validation_config.claims_validator:
        token_validation_config.claims_validator(decoded_token)

    return decoded_token


__all__ = ["validate_token", "TokenValidationConfig"]
