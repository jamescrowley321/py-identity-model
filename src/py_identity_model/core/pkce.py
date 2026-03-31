"""
PKCE (Proof Key for Code Exchange) utilities per RFC 7636.

Generates code verifiers and challenges for the OAuth 2.0 Authorization
Code Grant with PKCE extension.
"""

from base64 import urlsafe_b64encode
import hashlib
import secrets


_MIN_VERIFIER_LENGTH = 43
_MAX_VERIFIER_LENGTH = 128
_DEFAULT_VERIFIER_LENGTH = 128


def generate_code_verifier(length: int = _DEFAULT_VERIFIER_LENGTH) -> str:
    """Generate a cryptographically random code verifier.

    Args:
        length: Verifier length in characters (43-128 per RFC 7636).

    Returns:
        URL-safe random string suitable for use as a PKCE code verifier.

    Raises:
        ValueError: If *length* is outside the allowed range.
    """
    if length < _MIN_VERIFIER_LENGTH or length > _MAX_VERIFIER_LENGTH:
        msg = (
            f"Code verifier length must be between "
            f"{_MIN_VERIFIER_LENGTH} and {_MAX_VERIFIER_LENGTH}, got {length}"
        )
        raise ValueError(msg)
    return secrets.token_urlsafe(length)[:length]


def generate_code_challenge(
    verifier: str,
    method: str = "S256",
) -> str:
    """Derive a code challenge from a code verifier.

    Args:
        verifier: The code verifier string.
        method: Challenge method — ``"S256"`` (recommended) or ``"plain"``.

    Returns:
        The code challenge string.

    Raises:
        ValueError: If *method* is not ``"S256"`` or ``"plain"``, or
            if *verifier* length is outside the 43-128 range (RFC 7636).
    """
    if len(verifier) < _MIN_VERIFIER_LENGTH or len(verifier) > _MAX_VERIFIER_LENGTH:
        msg = (
            f"Code verifier length must be between "
            f"{_MIN_VERIFIER_LENGTH} and {_MAX_VERIFIER_LENGTH}, "
            f"got {len(verifier)}"
        )
        raise ValueError(msg)

    if method == "S256":
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        return urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    if method == "plain":
        return verifier
    msg = f"Unsupported code challenge method: {method}"
    raise ValueError(msg)


def generate_pkce_pair(
    method: str = "S256",
    verifier_length: int = _DEFAULT_VERIFIER_LENGTH,
) -> tuple[str, str]:
    """Generate a PKCE code verifier and challenge pair.

    Args:
        method: Challenge method — ``"S256"`` (default) or ``"plain"``.
        verifier_length: Length of the generated verifier (43-128).

    Returns:
        ``(code_verifier, code_challenge)`` tuple.
    """
    verifier = generate_code_verifier(verifier_length)
    challenge = generate_code_challenge(verifier, method)
    return verifier, challenge


__all__ = [
    "generate_code_challenge",
    "generate_code_verifier",
    "generate_pkce_pair",
]
