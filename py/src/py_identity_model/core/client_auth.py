"""HTTP Basic client authentication helpers (RFC 6749 §2.3.1)."""

from __future__ import annotations

from urllib.parse import quote


def basic_auth_credentials(client_id: str, client_secret: str) -> tuple[str, str]:
    """Return ``(client_id, client_secret)`` encoded for HTTP Basic auth.

    RFC 6749 §2.3.1 requires the client identifier and secret to be encoded
    using ``application/x-www-form-urlencoded`` (Appendix B) *before* they are
    used as the HTTP Basic username and password. HTTP client libraries (httpx
    included) base64-encode the pair verbatim, so a client_id or secret that
    contains reserved characters (``%``, ``+``, ``/``, ``:``, space) would be
    mangled by an authorization server that form-urldecodes per spec — the
    exact failure dynamically-registered secrets trigger.

    Percent-encode both values with an empty ``safe`` set so every reserved
    character (including the ``:`` Basic-auth separator) is escaped; clean
    ASCII credentials pass through unchanged, so this is a no-op for the common
    case and only corrects credentials that would otherwise be misdecoded.
    """
    return quote(client_id, safe=""), quote(client_secret, safe="")


__all__ = ["basic_auth_credentials"]
