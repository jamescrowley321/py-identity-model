from dataclasses import dataclass
from functools import lru_cache
from typing import List, Optional, Callable

from jwt import PyJWK, get_unverified_header, decode

from .discovery import (
    get_discovery_document,
    DiscoveryDocumentRequest,
    DiscoveryDocumentResponse,
)
from .exceptions import PyIdentityModelException
from .identity import ClaimsPrincipal, ClaimsIdentity, Claim
from .jwks import get_jwks, JwksRequest, JsonWebKey, JwksResponse


@dataclass
class TokenValidationConfig:
    perform_disco: bool
    key: Optional[dict] = None
    audience: Optional[str] = None
    algorithms: Optional[List[str]] = None
    issuer: Optional[str] = None
    subject: Optional[str] = None
    options: Optional[dict] = None
    claims_validator: Optional[Callable] = None


def _get_public_key_from_jwk(jwt: str, keys: List[JsonWebKey]) -> JsonWebKey:
    # TODO: clean up flow to prevent multiple decodes
    headers = get_unverified_header(jwt)
    filtered_keys = list(filter(lambda x: x.kid == headers.get("kid", None), keys))
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

    if not token_validation_config.key and not token_validation_config.algorithms:
        raise PyIdentityModelException(
            "TokenValidationConfig.key and TokenValidationConfig.algorithms are required if perform_disco is False"
        )

    return True


@lru_cache
def _get_disco_response(disco_doc_address: str) -> DiscoveryDocumentResponse:
    return get_discovery_document(DiscoveryDocumentRequest(address=disco_doc_address))


@lru_cache
def _get_jwks_response(jwks_uri: str) -> JwksResponse:
    return get_jwks(JwksRequest(address=jwks_uri))


def validate_token(
    jwt: str,
    token_validation_config: TokenValidationConfig,
    disco_doc_address: Optional[str] = None,
) -> dict:
    _validate_token_config(token_validation_config)

    if token_validation_config.perform_disco:
        disco_doc_response = _get_disco_response(disco_doc_address)

        if not disco_doc_response.is_successful:
            raise PyIdentityModelException(disco_doc_response.error)

        jwks_response = _get_jwks_response(disco_doc_response.jwks_uri)
        if not jwks_response.is_successful:
            raise PyIdentityModelException(jwks_response.error)

        if not jwks_response.keys:
            raise PyIdentityModelException("No keys available in JWKS response")

        token_validation_config.key = _get_public_key_from_jwk(
            jwt, jwks_response.keys
        ).as_dict()
        token_validation_config.algorithms = [token_validation_config.key["alg"]]

        decoded_token = decode(
            jwt,
            PyJWK(token_validation_config.key, token_validation_config.key["alg"]),
            audience=token_validation_config.audience,
            algorithms=token_validation_config.algorithms,
            issuer=disco_doc_response.issuer,
            options=token_validation_config.options,
        )
    else:
        if not token_validation_config.key:
            raise PyIdentityModelException("TokenValidationConfig.key is required")
        if not token_validation_config.algorithms:
            raise PyIdentityModelException(
                "TokenValidationConfig.algorithms is required"
            )

        decoded_token = decode(
            jwt,
            PyJWK(
                token_validation_config.key,
                token_validation_config.algorithms[0]
                if token_validation_config.algorithms
                else None,
            ),
            audience=token_validation_config.audience,
            algorithms=token_validation_config.algorithms,
            issuer=token_validation_config.issuer,
            options=token_validation_config.options,
        )

    if token_validation_config.claims_validator:
        token_validation_config.claims_validator(decoded_token)

    return decoded_token


def to_principal(
    token_claims: dict, authentication_type: str = "Bearer"
) -> ClaimsPrincipal:
    """
    Converts a dictionary of token claims (output from validate_token)
    into a ClaimsPrincipal object.

    Args:
        token_claims: Dictionary of claims returned from validate_token
        authentication_type: The authentication type (defaults to "Bearer")

    Returns:
        ClaimsPrincipal object containing the claims from the token
    """
    claims = []

    for claim_type, claim_value in token_claims.items():
        # Handle different claim value types
        if isinstance(claim_value, list):
            # Multiple values for the same claim type
            for value in claim_value:
                claims.append(Claim(claim_type=claim_type, value=str(value)))
        else:
            # Single value claim
            claims.append(Claim(claim_type=claim_type, value=str(claim_value)))

    # Create a ClaimsIdentity with the claims
    identity = ClaimsIdentity(claims=claims, authentication_type=authentication_type)

    # Create and return the ClaimsPrincipal
    return ClaimsPrincipal(identity=identity)


__all__ = ["validate_token", "TokenValidationConfig", "to_principal"]
