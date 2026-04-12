"""
JWT helper functions for py-identity-model.

This module contains JWT-related operations used by both sync and async implementations.
"""

from functools import lru_cache
import json

from jwt import PyJWK, decode
from jwt.exceptions import (
    ExpiredSignatureError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidSignatureError,
    InvalidTokenError,
)

from ..exceptions import (
    ConfigurationException,
    InvalidAudienceException,
    InvalidIssuerException,
    SignatureVerificationException,
    TokenExpiredException,
    TokenValidationException,
)
from ..logging_config import logger


@lru_cache(maxsize=128)
def _get_pyjwk(key_json: str, algorithm: str | None) -> PyJWK:
    """
    Cached PyJWK construction.

    PyJWK construction is expensive as it involves parsing and loading cryptographic keys.
    This cache significantly improves performance when validating multiple tokens with the
    same key.

    Args:
        key_json: JSON string representation of the key
        algorithm: Algorithm to use

    Returns:
        PyJWK instance
    """
    return PyJWK(json.loads(key_json), algorithm)


def _decode_jwt(  # noqa: PLR0913  # JWT validation requires these params per RFC 7519
    jwt_token: str,
    key: dict,
    algorithms: list[str],
    audience: str | None,
    issuer: str | list[str] | None,
    options: dict | None,
    leeway: float | None = None,
) -> dict:
    """
    Internal JWT decoding.

    Decodes and validates a JWT token using PyJWT. The PyJWK construction
    is cached via ``_get_pyjwk`` to avoid redundant cryptographic key loading.

    Args:
        jwt_token: The JWT token
        key: Public key as a dict
        algorithms: Allowed algorithms
        audience: Expected audience
        issuer: Expected issuer (string or list for multi-issuer)
        options: Additional validation options
        leeway: Clock skew tolerance in seconds

    Returns:
        Decoded claims
    """
    key_json = json.dumps(key, sort_keys=True)
    pyjwk = _get_pyjwk(key_json, algorithms[0] if algorithms else None)

    kwargs: dict = {
        "audience": audience,
        "algorithms": algorithms,
        "issuer": issuer,
        "options": options,
        "leeway": leeway if leeway is not None else 0,
    }

    return decode(jwt_token, pyjwk, **kwargs)


def decode_and_validate_jwt(  # noqa: PLR0913  # RFC 7519 §7.2 validation requires these params
    jwt: str,
    key: dict,
    algorithms: list[str],
    audience: str | None,
    issuer: str | list[str] | None,
    options: dict | None,
    leeway: float | None = None,
    subject: str | None = None,
) -> dict:
    """
    Decode and validate JWT with proper exception handling.

    Args:
        jwt: The JWT token to decode
        key: The public key to use for verification
        algorithms: List of allowed algorithms
        audience: Expected audience
        issuer: Expected issuer (single string or list for multi-tenant)
        options: Additional validation options
        leeway: Clock skew tolerance in seconds for exp/nbf claims
        subject: Expected ``sub`` claim.  Validated after decoding.

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
        # Guard against empty algorithms on direct API calls
        if not algorithms:
            raise ConfigurationException("algorithms must not be empty")

        # Guard against empty issuer list on direct API calls
        if isinstance(issuer, list) and len(issuer) == 0:
            raise ConfigurationException(
                "issuer must not be an empty list; omit or set to None to skip issuer validation"
            )

        decoded = _decode_jwt(
            jwt,
            key,
            algorithms,
            audience,
            issuer,
            options,
            leeway=leeway,
        )

        # Validate subject claim (PyJWT doesn't do this natively)
        if subject is not None and decoded.get("sub") != subject:
            raise TokenValidationException(
                "Invalid subject: token sub does not match expected value",
                token_part="payload",
            )

        return decoded
    except TokenValidationException:
        raise
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
        raise InvalidIssuerException("Invalid issuer", details={"error": str(e)}) from e
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


__all__ = [
    "decode_and_validate_jwt",
]
