"""
JWT Secured Authorization Request (JAR) utilities per RFC 9101.

Provides request object creation and authorization URL building for
passing authorization parameters as signed JWTs.
"""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import urlencode, urlparse
import uuid

import jwt as pyjwt


_RESERVED_CLAIMS = frozenset(
    {
        "iss",
        "aud",
        "iat",
        "nbf",
        "exp",
        "jti",
        "client_id",
        "response_type",
        "redirect_uri",
        "scope",
        "state",
        "nonce",
        "code_challenge",
        "code_challenge_method",
    }
)

_SUPPORTED_ALGORITHMS = {
    "ES256",
    "ES384",
    "ES512",
    "EdDSA",
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
}


def _validate_request_params(
    private_key: str | bytes,
    algorithm: str,
    client_id: str,
    audience: str,
    redirect_uri: str,
    response_type: str,
    lifetime: int,
    code_challenge: str | None,
    code_challenge_method: str | None,
    kid: str | None,
    extra_claims: dict[str, Any],
) -> None:
    """Validate all inputs for :func:`create_request_object`."""
    for name, value in (
        ("private_key", private_key),
        ("client_id", client_id),
        ("audience", audience),
        ("redirect_uri", redirect_uri),
        ("response_type", response_type),
    ):
        if not value:
            raise ValueError(f"{name} must not be empty")

    if algorithm not in _SUPPORTED_ALGORITHMS:
        msg = (
            f"Unsupported JAR algorithm: {algorithm}. "
            f"Supported: {sorted(_SUPPORTED_ALGORITHMS)}"
        )
        raise ValueError(msg)

    if lifetime <= 0:
        raise ValueError(f"lifetime must be positive, got {lifetime}")

    if (code_challenge is None) != (code_challenge_method is None):
        raise ValueError(
            "code_challenge and code_challenge_method must both be "
            "provided or both omitted"
        )

    for name, value in (
        ("code_challenge", code_challenge),
        ("code_challenge_method", code_challenge_method),
        ("kid", kid),
    ):
        if value is not None and not value:
            raise ValueError(f"{name} must be non-empty when provided")

    collisions = set(extra_claims) & _RESERVED_CLAIMS
    if collisions:
        raise ValueError(
            f"extra_claims cannot override reserved claims: "
            f"{sorted(collisions)}"
        )


def create_request_object(
    private_key: str | bytes,
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
    kid: str | None = None,
    **extra_claims: Any,
) -> str:
    """Create a signed JWT request object per RFC 9101.

    The request object contains authorization parameters as JWT claims,
    ensuring request integrity through signing.  The JWT ``typ`` header
    is set to ``"oauth-authz-req+jwt"`` per RFC 9101 Section 10.2.

    Args:
        private_key: PEM-encoded private key for signing (bytes or str).
        algorithm: Signing algorithm (e.g. ``"ES256"``, ``"RS256"``,
            ``"EdDSA"``).
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
        kid: Key ID to include in the JWT header for key lookup.
        **extra_claims: Additional claims to include in the request object.

    Returns:
        The signed JWT string.

    Raises:
        ValueError: If *algorithm* is not supported, required parameters
            are empty, *lifetime* is not positive, *code_challenge* and
            *code_challenge_method* are not both provided, or
            *extra_claims* contains a reserved claim name.
    """
    _validate_request_params(
        private_key,
        algorithm,
        client_id,
        audience,
        redirect_uri,
        response_type,
        lifetime,
        code_challenge,
        code_challenge_method,
        kid,
        extra_claims,
    )

    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": client_id,
        "aud": audience,
        "iat": now,
        "nbf": now,
        "exp": now + lifetime,
        "jti": str(uuid.uuid4()),
        "client_id": client_id,
        "response_type": response_type,
        "redirect_uri": redirect_uri,
        "scope": scope,
    }

    for name, value in (
        ("state", state),
        ("nonce", nonce),
        ("code_challenge", code_challenge),
        ("code_challenge_method", code_challenge_method),
    ):
        if value is not None:
            claims[name] = value

    claims.update(extra_claims)

    headers: dict[str, str] = {"typ": "oauth-authz-req+jwt"}
    if kid is not None:
        headers["kid"] = kid

    return pyjwt.encode(
        claims, private_key, algorithm=algorithm, headers=headers
    )


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

    parsed = urlparse(authorization_endpoint)
    separator = "&" if parsed.query else "?"
    return f"{authorization_endpoint}{separator}{urlencode(params)}"


__all__ = [
    "build_jar_authorization_url",
    "create_request_object",
]
