"""
Authorization callback response parsing for OAuth 2.0 / OpenID Connect.

Parses redirect URIs from authorization callbacks into typed response objects,
supporting both query string (code flow) and fragment (implicit flow) parameters.

Reference: RFC 6749 Section 4.1.2, OpenID Connect Core Section 3.1.2.5
"""

from dataclasses import dataclass
from typing import ClassVar
from urllib.parse import parse_qs, urlparse

from ..oidc_constants import AuthorizeResponse as AuthorizeResponseParams
from .models import _GuardedResponseMixin


@dataclass
class AuthorizeCallbackResponse(_GuardedResponseMixin):
    """Parsed OAuth 2.0 / OIDC authorization callback response.

    Fields like ``code``, ``access_token``, and ``state`` are guarded:
    accessing them raises ``FailedResponseAccessError`` when
    ``is_successful`` is ``False``.  The ``error`` and
    ``error_description`` fields are only accessible when the response
    represents an error (``is_successful is False``).
    """

    _guarded_fields: ClassVar[frozenset[str]] = frozenset(
        {
            "code",
            "access_token",
            "identity_token",
            "token_type",
            "expires_in",
            "scope",
            "state",
            "session_state",
            "issuer",
        }
    )

    is_successful: bool
    raw: str
    values: dict[str, str]

    # OAuth 2.0 / OIDC response parameters (guarded)
    code: str | None = None
    access_token: str | None = None
    identity_token: str | None = None
    token_type: str | None = None
    expires_in: str | None = None
    scope: str | None = None
    state: str | None = None
    session_state: str | None = None
    issuer: str | None = None

    # Error fields
    error: str | None = None
    error_description: str | None = None


# Mapping from AuthorizeResponse enum values to dataclass field names.
# Most map 1:1; only id_token differs (field is ``identity_token``).
_PARAM_TO_FIELD: dict[str, str] = {
    AuthorizeResponseParams.CODE.value: "code",
    AuthorizeResponseParams.ACCESS_TOKEN.value: "access_token",
    AuthorizeResponseParams.IDENTITY_TOKEN.value: "identity_token",
    AuthorizeResponseParams.TOKEN_TYPE.value: "token_type",
    AuthorizeResponseParams.EXPIRES_IN.value: "expires_in",
    AuthorizeResponseParams.SCOPE.value: "scope",
    AuthorizeResponseParams.STATE.value: "state",
    AuthorizeResponseParams.SESSION_STATE.value: "session_state",
    AuthorizeResponseParams.ISSUER.value: "issuer",
    AuthorizeResponseParams.ERROR.value: "error",
    AuthorizeResponseParams.ERROR_DESCRIPTION.value: "error_description",
}


def parse_authorize_callback_response(
    redirect_uri: str,
) -> AuthorizeCallbackResponse:
    """Parse an OAuth 2.0 / OIDC authorization callback redirect URI.

    Extracts parameters from the URL fragment (implicit / hybrid flows) or
    query string (authorization code flow).  Fragment takes precedence when
    both are present, matching standard browser behavior where the
    authorization server places parameters in one location.

    Args:
        redirect_uri: The full callback URL received from the authorization
            server (e.g. ``https://app.example.com/callback?code=abc&state=xyz``).

    Returns:
        An ``AuthorizeCallbackResponse`` with ``is_successful=False`` when the
        URL contains an ``error`` parameter, or ``True`` otherwise.
    """
    parsed = urlparse(redirect_uri)
    params_str = parsed.fragment or parsed.query

    # parse_qs returns dict[str, list[str]]; flatten to first value
    raw_params = parse_qs(params_str)
    values: dict[str, str] = {k: v[0] for k, v in raw_params.items()}

    # Map known parameters to dataclass fields
    field_values: dict[str, str] = {}
    for param_name, field_name in _PARAM_TO_FIELD.items():
        if param_name in values:
            field_values[field_name] = values[param_name]

    has_error = "error" in field_values

    return AuthorizeCallbackResponse(
        is_successful=not has_error,
        raw=redirect_uri,
        values=values,
        **field_values,
    )


__all__ = [
    "AuthorizeCallbackResponse",
    "parse_authorize_callback_response",
]
