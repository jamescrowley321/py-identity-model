"""
Authorization URL builder for OAuth 2.0 / OpenID Connect.

Constructs the authorization endpoint URL with all required and optional
query parameters for the authorization code flow.
"""

from urllib.parse import urlencode


def build_authorization_url(
    authorization_endpoint: str,
    client_id: str,
    redirect_uri: str,
    scope: str = "openid",
    response_type: str = "code",
    state: str | None = None,
    nonce: str | None = None,
    code_challenge: str | None = None,
    code_challenge_method: str | None = None,
    **extra_params: str,
) -> str:
    """Build an OAuth 2.0 / OIDC authorization endpoint URL.

    Constructs a URL with query parameters for redirecting the user to
    the authorization server.  PKCE parameters (``code_challenge`` and
    ``code_challenge_method``) are included when provided.

    Args:
        authorization_endpoint: The authorization server's authorize URL
            (typically from the discovery document).
        client_id: The registered client identifier.
        redirect_uri: The callback URL registered with the authorization server.
        scope: Space-delimited scopes (default ``"openid"``).
        response_type: OAuth 2.0 response type (default ``"code"``).
        state: Opaque CSRF protection value.
        nonce: OpenID Connect nonce for replay protection.
        code_challenge: PKCE code challenge (from :func:`generate_code_challenge`).
        code_challenge_method: PKCE method — ``"S256"`` or ``"plain"``.
        **extra_params: Additional query parameters.

    Returns:
        The full authorization URL ready for redirect.
    """
    params: dict[str, str] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "response_type": response_type,
    }
    if state is not None:
        params["state"] = state
    if nonce is not None:
        params["nonce"] = nonce
    if code_challenge is not None:
        params["code_challenge"] = code_challenge
    if code_challenge_method is not None:
        params["code_challenge_method"] = code_challenge_method
    params.update(extra_params)

    separator = "&" if "?" in authorization_endpoint else "?"
    return f"{authorization_endpoint}{separator}{urlencode(params)}"


__all__ = ["build_authorization_url"]
