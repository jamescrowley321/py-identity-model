from dataclasses import dataclass
from typing import List, Optional

from jose import jwt as jwt_utils

from .discovery import get_discovery_document, DiscoveryDocumentRequest
from .exceptions import PyIdentityModelException
from .jwks import get_jwks, JwksRequest, JsonWebKey


@dataclass
class TokenValidationConfig:
    perform_disco: bool
    key: Optional[dict] = None
    audience: Optional[str] = None
    algorithms: Optional[List[str]] = None
    issuer: Optional[List[str]] = None
    subject: Optional[str] = None
    options: Optional[dict] = None


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
    if token_validation_config:
        return True

    if (
        not token_validation_config.key
        and not token_validation_config.algorithms
    ):
        raise PyIdentityModelException(
            "TokenValidationConfig.key and TokenValidationConfig.algorithms are required if perform_disco is False"
        )


# TODO: Use correct validation methodology -  https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.221043800.1718553743.1594267304-296270163.1594267304#create-the-jwt-validation-decorator
def validate_token(
    jwt: str,
    token_validation_config: TokenValidationConfig,
    disco_doc_address: str = None,
) -> dict:
    _validate_token_config(token_validation_config)

    if token_validation_config.perform_disco:
        disco_doc_response = get_discovery_document(
            DiscoveryDocumentRequest(address=disco_doc_address)
        )

        if not disco_doc_response.is_successful:
            raise PyIdentityModelException(disco_doc_response.error)

        jwks_response = get_jwks(
            JwksRequest(address=disco_doc_response.jwks_uri)
        )
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
    return decoded_token


__all__ = ["validate_token", "TokenValidationConfig"]
