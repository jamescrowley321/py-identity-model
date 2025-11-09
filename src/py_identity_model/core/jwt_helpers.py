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


@lru_cache(maxsize=256)
def _decode_jwt_cached(
    jwt: str,
    key_json: str,
    algorithms_tuple: tuple[str, ...],
    audience: str | None,
    issuer: str | None,
    options_json: str | None,
) -> dict:
    """
    Internal cached JWT decoding.

    Caches decoded tokens to avoid redundant signature verification when
    the same JWT is validated multiple times.

    Args:
        jwt: The JWT token
        key_json: Serialized key
        algorithms_tuple: Algorithms as tuple (hashable)
        audience: Expected audience
        issuer: Expected issuer
        options_json: Serialized options

    Returns:
        Decoded claims
    """
    pyjwk = _get_pyjwk(
        key_json, algorithms_tuple[0] if algorithms_tuple else None
    )
    options = json.loads(options_json) if options_json else None

    return decode(
        jwt,
        pyjwk,
        audience=audience,
        algorithms=list(algorithms_tuple),
        issuer=issuer,
        options=options,
    )


def decode_and_validate_jwt(
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
        # Convert to hashable types for caching
        key_json = json.dumps(key, sort_keys=True)
        algorithms_tuple = tuple(algorithms) if algorithms else ()
        options_json = json.dumps(options, sort_keys=True) if options else None

        return _decode_jwt_cached(
            jwt,
            key_json,
            algorithms_tuple,
            audience,
            issuer,
            options_json,
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


__all__ = [
    "decode_and_validate_jwt",
]
