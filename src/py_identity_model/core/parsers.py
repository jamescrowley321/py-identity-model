"""
Parsing functions for py-identity-model.

This module contains parsing logic used by both sync and async implementations.
"""

from jwt import get_unverified_header

from ..exceptions import TokenValidationException
from ..logging_config import logger
from .models import JsonWebKey, JsonWebKeyParameterNames


# ============================================================================
# JWKS Parsing
# ============================================================================


def jwks_from_dict(keys_dict: dict) -> JsonWebKey:
    """
    Parse a JWKS dictionary into a JsonWebKey object.

    Args:
        keys_dict: Dictionary containing JWK parameters

    Returns:
        JsonWebKey: Parsed JWK object
    """
    return JsonWebKey(
        # Required parameter
        kty=keys_dict.get("kty") or "",
        # Optional parameters for all keys
        use=keys_dict.get("use"),
        key_ops=keys_dict.get("key_ops"),
        alg=keys_dict.get("alg"),
        kid=keys_dict.get("kid"),
        # Optional JWK parameters
        x5u=keys_dict.get("x5u"),
        x5c=keys_dict.get("x5c"),
        x5t=keys_dict.get("x5t"),
        x5t_s256=keys_dict.get(JsonWebKeyParameterNames.X5T_S256.value),
        # Parameters for Elliptic Curve Keys
        crv=keys_dict.get("crv"),
        x=keys_dict.get("x"),
        y=keys_dict.get("y"),
        d=keys_dict.get("d"),
        # Parameters for RSA Keys
        n=keys_dict.get("n"),
        e=keys_dict.get("e"),
        p=keys_dict.get("p"),
        q=keys_dict.get("q"),
        dp=keys_dict.get("dp"),
        dq=keys_dict.get("dq"),
        qi=keys_dict.get("qi"),
        oth=keys_dict.get("oth"),
        # Parameters for Symmetric Keys
        k=keys_dict.get("k"),
    )


def get_public_key_from_jwk(jwt: str, keys: list[JsonWebKey]) -> JsonWebKey:
    """
    Find the public key from JWKS that matches the JWT's kid.

    Args:
        jwt: The JWT token
        keys: List of JsonWebKey objects from JWKS

    Returns:
        JsonWebKey: The matching key

    Raises:
        TokenValidationException: If no matching key is found
    """
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


__all__ = [
    "get_public_key_from_jwk",
    "jwks_from_dict",
]
