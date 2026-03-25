"""
JWT Secured Authorization Request (JAR) utilities per RFC 9101.

Provides request object creation and authorization URL building for
passing authorization parameters as signed JWTs.
"""

from __future__ import annotations

import time
from urllib.parse import urlencode

import jwt as pyjwt


_RESERVED_CLAIMS = frozenset(
    {
        "iss",
        "aud",
        "iat",
        "nbf",
        "exp",
        "client_id",
        "response_type",
        "redirect_uri",
        "scope",
    }
)

_SUPPORTED_ALGORITHMS = {
    "ES256",
    "ES384",
    "ES512",
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
}


def create_request_object(
    private_key: bytes,
    algorithm: str,
    client_id: str,
    audience: str,
    redirect_uri: str,
    scope: str = "openid",
    response_type: str = "code",
    state: str | None = None,
    nonce: str | None = None,
    code_challenge: str | None = None,
    code_challenge_method: str | None = None,
    lifetime: int = 300,
    **extra_claims: str,
) -> str:
    """Create a signed JWT request object per RFC 9101.

    The request object contains authorization parameters as JWT claims,
    ensuring request integrity through signing.

    Args:
        private_key: PEM-encoded private key bytes for signing.
        algorithm: Signing algorithm (e.g. ``"ES256"``, ``"RS256"``).
        client_id: Client identifier - becomes both ``iss`` and
            ``client_id`` claims.
        audience: Authorization server issuer - becomes ``aud`` claim.
        redirect_uri: Registered redirect URI.
        scope: Space-delimited scopes (default ``"openid"``).
        response_type: OAuth 2.0 response type (default ``"code"``).
        state: CSRF protection value.
        nonce: OpenID Connect nonce for replay protection.
        code_challenge: PKCE code challenge.
        code_challenge_method: PKCE method (``"S256"`` or ``"plain"``).
        lifetime: JWT validity in seconds (default 300).
        **extra_claims: Additional claims to include in the request object.

    Returns:
        The signed JWT string.

    Raises:
        ValueError: If *algorithm* is not supported, *lifetime* is not
            positive, or *extra_claims* contains a reserved claim name.
    """
    if algorithm not in _SUPPORTED_ALGORITHMS:
        msg = (
            f"Unsupported JAR algorithm: {algorithm}. "
            f"Supported: {sorted(_SUPPORTED_ALGORITHMS)}"
        )
        raise ValueError(msg)

    if lifetime <= 0:
        raise ValueError(f"lifetime must be positive, got {lifetime}")

    collisions = set(extra_claims) & _RESERVED_CLAIMS
    if collisions:
        raise ValueError(
            f"extra_claims cannot override reserved claims: "
            f"{sorted(collisions)}"
        )

    now = int(time.time())
    claims: dict[str, str | int] = {
        "iss": client_id,
        "aud": audience,
        "iat": now,
        "nbf": now,
        "exp": now + lifetime,
        "client_id": client_id,
        "response_type": response_type,
        "redirect_uri": redirect_uri,
        "scope": scope,
    }

    if state is not None:
        claims["state"] = state
    if nonce is not None:
        claims["nonce"] = nonce
    if code_challenge is not None:
        claims["code_challenge"] = code_challenge
    if code_challenge_method is not None:
        claims["code_challenge_method"] = code_challenge_method

    claims.update(extra_claims)

    return pyjwt.encode(claims, private_key, algorithm=algorithm)


def build_jar_authorization_url(
    authorization_endpoint: str,
    client_id: str,
    request_object: str,
    scope: str | None = None,
    response_type: str | None = None,
) -> str:
    """Build an authorization URL with a JAR ``request`` parameter.

    Per RFC 9101 Section 6.3, ``client_id`` MUST appear as a query
    parameter and ``scope``/``response_type`` SHOULD be duplicated
    outside the request object for backward compatibility.

    Args:
        authorization_endpoint: The authorization server's authorize URL.
        client_id: The registered client identifier.
        request_object: Signed JWT from :func:`create_request_object`.
        scope: Optional scope to duplicate in query params.
        response_type: Optional response_type to duplicate in query params.

    Returns:
        The full authorization URL with the ``request`` parameter.
    """
    params: dict[str, str] = {
        "client_id": client_id,
        "request": request_object,
    }
    if scope is not None:
        params["scope"] = scope
    if response_type is not None:
        params["response_type"] = response_type

    separator = "&" if "?" in authorization_endpoint else "?"
    return f"{authorization_endpoint}{separator}{urlencode(params)}"


__all__ = [
    "build_jar_authorization_url",
    "create_request_object",
]
