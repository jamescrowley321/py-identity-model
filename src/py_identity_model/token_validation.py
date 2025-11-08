from collections.abc import Callable
from dataclasses import dataclass
from functools import lru_cache

from jwt import PyJWK, decode, get_unverified_header
from jwt.exceptions import (
    ExpiredSignatureError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidSignatureError,
    InvalidTokenError,
)

from .discovery import (
    DiscoveryDocumentRequest,
    DiscoveryDocumentResponse,
    get_discovery_document,
)
from .exceptions import (
    ConfigurationException,
    InvalidAudienceException,
    InvalidIssuerException,
    SignatureVerificationException,
    TokenExpiredException,
    TokenValidationException,
)
from .identity import Claim, ClaimsIdentity, ClaimsPrincipal
from .jwks import JsonWebKey, JwksRequest, JwksResponse, get_jwks
from .logging_config import logger
from .logging_utils import redact_token


@dataclass
class TokenValidationConfig:
    perform_disco: bool
    key: dict | None = None
    audience: str | None = None
    algorithms: list[str] | None = None
    issuer: str | None = None
    subject: str | None = None
    options: dict | None = None
    claims_validator: Callable | None = None


def _get_public_key_from_jwk(jwt: str, keys: list[JsonWebKey]) -> JsonWebKey:
    headers = get_unverified_header(jwt)
    kid = headers.get("kid")
    logger.debug(f"Looking for key with kid: {kid}")

    filtered_keys = list(filter(lambda x: x.kid == kid, keys))
    if not filtered_keys:
        available_kids = [k.kid for k in keys if k.kid]
        logger.error(
            f"No matching kid found. Requested: {kid}, Available: {available_kids}",
        )
        raise TokenValidationException(
            f"No matching kid found: {kid}",
            token_part="header",
            details={"kid": kid, "available_kids": available_kids},
        )

    key = filtered_keys[0]
    if not key.alg:
        key.alg = headers["alg"]

    logger.debug(f"Found matching key with kid: {kid}, alg: {key.alg}")
    return key


def _validate_token_config(
    token_validation_config: TokenValidationConfig,
) -> None:
    """
    Validate token validation configuration.

    Args:
        token_validation_config: Configuration to validate

    Raises:
        ConfigurationException: If configuration is invalid
    """
    if token_validation_config.perform_disco:
        return

    if (
        not token_validation_config.key
        and not token_validation_config.algorithms
    ):
        raise ConfigurationException(
            "TokenValidationConfig.key and TokenValidationConfig.algorithms are required if perform_disco is False",
        )


@lru_cache
def _get_disco_response(disco_doc_address: str) -> DiscoveryDocumentResponse:
    return get_discovery_document(
        DiscoveryDocumentRequest(address=disco_doc_address),
    )


@lru_cache
def _get_jwks_response(jwks_uri: str) -> JwksResponse:
    return get_jwks(JwksRequest(address=jwks_uri))


def _decode_and_validate_jwt(
    jwt: str,
    key: dict,
    algorithms: list[str],
    audience: str | None,
    issuer: str | None,
    options: dict | None,
) -> dict:
    """
    Decode and validate JWT with proper exception handling.

    Args:
        jwt: The JWT token to decode
        key: The public key to use for verification
        algorithms: List of allowed algorithms
        audience: Expected audience
        issuer: Expected issuer
        options: Additional validation options

    Returns:
        Decoded token claims

    Raises:
        TokenExpiredException: If token has expired
        InvalidAudienceException: If audience is invalid
        InvalidIssuerException: If issuer is invalid
        SignatureVerificationException: If signature is invalid
        TokenValidationException: For other token validation errors
    """
    try:
        return decode(
            jwt,
            PyJWK(key, algorithms[0] if algorithms else None),
            audience=audience,
            algorithms=algorithms,
            issuer=issuer,
            options=options,
        )
    except ExpiredSignatureError as e:
        logger.error(f"Token has expired: {e!s}")
        raise TokenExpiredException(
            "Token has expired",
            details={"error": str(e)},
        ) from e
    except InvalidAudienceError as e:
        logger.error(f"Invalid audience: {e!s}")
        raise InvalidAudienceException(
            "Invalid audience",
            details={"error": str(e)},
        ) from e
    except InvalidIssuerError as e:
        logger.error(f"Invalid issuer: {e!s}")
        raise InvalidIssuerException(
            "Invalid issuer", details={"error": str(e)}
        ) from e
    except InvalidSignatureError as e:
        logger.error(f"Invalid signature: {e!s}")
        raise SignatureVerificationException(
            "Invalid signature",
            details={"error": str(e)},
        ) from e
    except InvalidTokenError as e:
        logger.error(f"Invalid token: {e!s}")
        raise TokenValidationException(
            f"Invalid token: {e!s}",
            details={"error": str(e)},
        ) from e


def validate_token(
    jwt: str,
    token_validation_config: TokenValidationConfig,
    disco_doc_address: str | None = None,
) -> dict:
    logger.info(f"Starting token validation, token: {redact_token(jwt)}")
    logger.debug(
        f"Validation config - perform_disco: {token_validation_config.perform_disco}, "
        f"audience: {token_validation_config.audience}",
    )

    _validate_token_config(token_validation_config)

    if token_validation_config.perform_disco:
        disco_doc_response = _get_disco_response(disco_doc_address)

        if not disco_doc_response.is_successful:
            error_msg = (
                disco_doc_response.error or "Discovery document request failed"
            )
            logger.error(f"Discovery failed: {error_msg}")
            raise TokenValidationException(error_msg)

        jwks_response = _get_jwks_response(disco_doc_response.jwks_uri)
        if not jwks_response.is_successful:
            error_msg = jwks_response.error or "JWKS request failed"
            logger.error(f"JWKS fetch failed: {error_msg}")
            raise TokenValidationException(error_msg)

        if not jwks_response.keys:
            error_msg = "No keys available in JWKS response"
            logger.error(error_msg)
            raise TokenValidationException(error_msg)

        token_validation_config.key = _get_public_key_from_jwk(
            jwt,
            jwks_response.keys,
        ).as_dict()
        token_validation_config.algorithms = [
            token_validation_config.key["alg"],
        ]

        decoded_token = _decode_and_validate_jwt(
            jwt=jwt,
            key=token_validation_config.key,
            algorithms=token_validation_config.algorithms,
            audience=token_validation_config.audience,
            issuer=disco_doc_response.issuer,
            options=token_validation_config.options,
        )
    else:
        if not token_validation_config.key:
            raise ConfigurationException(
                "TokenValidationConfig.key is required",
            )
        if not token_validation_config.algorithms:
            raise ConfigurationException(
                "TokenValidationConfig.algorithms is required",
            )

        decoded_token = _decode_and_validate_jwt(
            jwt=jwt,
            key=token_validation_config.key,
            algorithms=token_validation_config.algorithms,
            audience=token_validation_config.audience,
            issuer=token_validation_config.issuer,
            options=token_validation_config.options,
        )

    if token_validation_config.claims_validator:
        try:
            token_validation_config.claims_validator(decoded_token)
        except Exception as e:
            logger.error(f"Claims validation failed: {e!s}")
            raise TokenValidationException(
                f"Claims validation failed: {e!s}",
                token_part="payload",
                details={"error": str(e)},
            ) from e

    logger.info(
        f"Token validation successful for subject: {decoded_token.get('sub', 'unknown')}",
    )
    logger.debug(f"Decoded token claims: {list(decoded_token.keys())}")
    return decoded_token


def to_principal(
    token_claims: dict,
    authentication_type: str = "Bearer",
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
            claims.extend(
                Claim(claim_type=claim_type, value=str(value))
                for value in claim_value
            )
        else:
            # Single value claim
            claims.append(Claim(claim_type=claim_type, value=str(claim_value)))

    # Create a ClaimsIdentity with the claims
    identity = ClaimsIdentity(
        claims=claims,
        authentication_type=authentication_type,
    )

    # Create and return the ClaimsPrincipal
    return ClaimsPrincipal(identity=identity)


__all__ = ["TokenValidationConfig", "to_principal", "validate_token"]
