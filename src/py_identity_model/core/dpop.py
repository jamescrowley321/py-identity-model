"""
DPoP (Demonstrating Proof of Possession) utilities per RFC 9449.

Provides key pair generation, DPoP proof JWT creation, and access token
hash computation for binding OAuth 2.0 tokens to a client's private key.
"""

from __future__ import annotations

from base64 import urlsafe_b64encode
import hashlib
import json
import time
import uuid

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
import jwt as pyjwt


# Mapping from JWT algorithm to EC curve
_EC_CURVES: dict[str, ec.EllipticCurve] = {
    "ES256": ec.SECP256R1(),
    "ES384": ec.SECP384R1(),
    "ES512": ec.SECP521R1(),
}

_SUPPORTED_ALGORITHMS = {"ES256", "ES384", "ES512", "RS256"}


def _int_to_b64url(n: int, length: int) -> str:
    """Encode an integer as base64url without padding."""
    return (
        urlsafe_b64encode(n.to_bytes(length, "big"))
        .rstrip(b"=")
        .decode("ascii")
    )


class DPoPKey:
    """Manages a DPoP asymmetric key pair.

    Generate via :func:`generate_dpop_key`.  The key pair is immutable
    and thread-safe after construction.

    Args:
        algorithm: The signing algorithm (``"ES256"``, ``"RS256"``, etc.).
    """

    def __init__(self, algorithm: str = "ES256") -> None:
        if algorithm not in _SUPPORTED_ALGORITHMS:
            msg = (
                f"Unsupported DPoP algorithm: {algorithm}. "
                f"Supported: {sorted(_SUPPORTED_ALGORITHMS)}"
            )
            raise ValueError(msg)

        self._algorithm = algorithm
        self._private_key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey

        if algorithm in _EC_CURVES:
            self._private_key = ec.generate_private_key(_EC_CURVES[algorithm])
        else:
            self._private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048
            )

    @property
    def algorithm(self) -> str:
        """The signing algorithm."""
        return self._algorithm

    @property
    def private_key_pem(self) -> bytes:
        """PEM-encoded private key bytes."""
        return self._private_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )

    @property
    def public_jwk(self) -> dict:
        """Public key as a JWK dict suitable for the DPoP proof ``jwk`` header."""
        pub = self._private_key.public_key()

        if isinstance(pub, ec.EllipticCurvePublicKey):
            numbers = pub.public_numbers()
            curve_name = {
                "secp256r1": "P-256",
                "secp384r1": "P-384",
                "secp521r1": "P-521",
            }[pub.curve.name]
            key_size = (pub.curve.key_size + 7) // 8
            return {
                "kty": "EC",
                "crv": curve_name,
                "x": _int_to_b64url(numbers.x, key_size),
                "y": _int_to_b64url(numbers.y, key_size),
            }

        # RSA
        numbers = pub.public_numbers()  # type: ignore[union-attr]
        return {
            "kty": "RSA",
            "n": _int_to_b64url(numbers.n, (numbers.n.bit_length() + 7) // 8),
            "e": _int_to_b64url(numbers.e, 3),
        }

    @property
    def jwk_thumbprint(self) -> str:
        """JWK Thumbprint (RFC 7638) for use as ``dpop_jkt`` parameter."""
        jwk = self.public_jwk
        # Per RFC 7638: lexicographically sorted required members
        if jwk.get("kty") == "EC":
            thumbprint_input = json.dumps(
                {
                    "crv": jwk["crv"],
                    "kty": jwk["kty"],
                    "x": jwk["x"],
                    "y": jwk["y"],
                },
                separators=(",", ":"),
                sort_keys=True,
            )
        else:
            thumbprint_input = json.dumps(
                {"e": jwk["e"], "kty": jwk["kty"], "n": jwk["n"]},
                separators=(",", ":"),
                sort_keys=True,
            )
        digest = hashlib.sha256(thumbprint_input.encode("ascii")).digest()
        return urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def generate_dpop_key(algorithm: str = "ES256") -> DPoPKey:
    """Generate a new DPoP key pair.

    Args:
        algorithm: Signing algorithm — ``"ES256"`` (default, recommended),
            ``"ES384"``, ``"ES512"``, or ``"RS256"``.

    Returns:
        A :class:`DPoPKey` with a fresh key pair.
    """
    return DPoPKey(algorithm)


def compute_ath(access_token: str) -> str:
    """Compute the access token hash (``ath``) claim value.

    Used when sending a DPoP proof alongside a bound access token to a
    resource server.

    Args:
        access_token: The access token string.

    Returns:
        Base64url-encoded SHA-256 hash of the access token.
    """
    digest = hashlib.sha256(access_token.encode("ascii")).digest()
    return urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def create_dpop_proof(
    key: DPoPKey,
    method: str,
    uri: str,
    access_token: str | None = None,
    nonce: str | None = None,
) -> str:
    """Create a signed DPoP proof JWT (RFC 9449).

    Args:
        key: The :class:`DPoPKey` to sign the proof with.
        method: HTTP method (e.g. ``"POST"``, ``"GET"``).
        uri: The full HTTP URI of the request.
        access_token: If provided, includes the ``ath`` claim (required
            for resource server requests with bound tokens).
        nonce: Server-provided DPoP nonce (from a previous ``DPoP-Nonce``
            response header).

    Returns:
        The signed DPoP proof JWT string.
    """
    headers = {
        "typ": "dpop+jwt",
        "alg": key.algorithm,
        "jwk": key.public_jwk,
    }

    payload: dict = {
        "jti": str(uuid.uuid4()),
        "htm": method.upper(),
        "htu": uri,
        "iat": int(time.time()),
    }

    if access_token is not None:
        payload["ath"] = compute_ath(access_token)

    if nonce is not None:
        payload["nonce"] = nonce

    return pyjwt.encode(
        payload, key.private_key_pem, algorithm=key.algorithm, headers=headers
    )


def build_dpop_headers(
    proof: str,
    access_token: str | None = None,
) -> dict[str, str]:
    """Build HTTP headers dict with DPoP proof and optional Authorization.

    For **token endpoint** requests, only the ``DPoP`` header is needed.
    For **resource server** requests, both ``DPoP`` and
    ``Authorization: DPoP <token>`` headers are included.

    Args:
        proof: The signed DPoP proof JWT.
        access_token: If provided, adds ``Authorization: DPoP <token>`` header.

    Returns:
        Dict of HTTP headers to include in the request.
    """
    headers: dict[str, str] = {"DPoP": proof}
    if access_token is not None:
        headers["Authorization"] = f"DPoP {access_token}"
    return headers


__all__ = [
    "DPoPKey",
    "build_dpop_headers",
    "compute_ath",
    "create_dpop_proof",
    "generate_dpop_key",
]
