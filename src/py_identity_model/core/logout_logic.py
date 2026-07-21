"""Back-Channel Logout token validation logic.

Pure, protocol-agnostic claim validation shared by the synchronous and
asynchronous logout wrappers. Contains no I/O: the standard JWT validation
(signature, ``iss``, ``aud``, ``iat``, ``exp``) is performed by the existing
``validate_token`` path; this module enforces only the additional rules that
are unique to Logout Tokens (OpenID Connect Back-Channel Logout 1.0 §2.4).
"""

from __future__ import annotations

from ..exceptions import LogoutTokenValidationException
from ..oidc_constants import BackChannelLogoutRequest, Events


# The event member that MUST be present in a Logout Token's ``events`` claim
# (Back-Channel Logout 1.0 §2.4, validation step 4).
BACKCHANNEL_LOGOUT_EVENT = Events.BACK_CHANNEL_LOGOUT.value

# The request parameter name providers use to POST the Logout Token to the
# RP's ``backchannel_logout_uri`` (Back-Channel Logout 1.0 §2.5).
LOGOUT_TOKEN_PARAM = BackChannelLogoutRequest.LOGOUT_TOKEN.value

# Claims that MUST be present in a Logout Token (§2.4 validation step 2).
# ``iss``/``aud``/``iat`` are also checked by standard JWT validation, but are
# enumerated here so a rule violation produces a precise, self-contained error
# and so the pure claim check is complete on its own.
_REQUIRED_CLAIMS = ("iss", "aud", "iat", "jti", "events")


def validate_logout_token_claims(claims: dict) -> None:
    """Validate the Logout-Token-specific claim rules (Back-Channel Logout 1.0 §2.4).

    Assumes the JWT signature, ``iss``, ``aud``, ``iat`` and (when present)
    ``exp`` have ALREADY been verified by the standard token-validation path.
    This function enforces only the rules unique to Logout Tokens:

    2. ``iss``, ``aud``, ``iat``, ``jti`` and ``events`` MUST be present.
    4. ``events`` MUST be a JSON object containing the
       ``http://schemas.openid.net/event/backchannel-logout`` member.
    3. ``sub`` and/or ``sid`` MUST be present (at least one).
    5. A ``nonce`` claim MUST NOT be present (a Logout Token must not be
       usable as an ID Token).

    Args:
        claims: The decoded (and already signature/iss/aud/exp-validated)
            JWT claim set.

    Raises:
        LogoutTokenValidationException: If any Logout-Token rule is violated.
    """
    # Step 2 — required claims.
    for required in _REQUIRED_CLAIMS:
        if required not in claims:
            raise LogoutTokenValidationException(
                f"Logout token missing required '{required}' claim",
                token_part="payload",
            )

    # Step 5 — a Logout Token MUST NOT contain a ``nonce`` claim.
    if "nonce" in claims:
        raise LogoutTokenValidationException(
            "Logout token must not contain a 'nonce' claim",
            token_part="payload",
        )

    # Step 3 — at least one of ``sub`` / ``sid`` must be present.
    if claims.get("sub") is None and claims.get("sid") is None:
        raise LogoutTokenValidationException(
            "Logout token must contain at least one of 'sub' or 'sid'",
            token_part="payload",
        )

    # Step 4 — ``events`` must be a JSON object containing the
    # backchannel-logout member.
    events = claims.get("events")
    if not isinstance(events, dict):
        raise LogoutTokenValidationException(
            "Logout token 'events' claim must be a JSON object",
            token_part="payload",
        )
    if BACKCHANNEL_LOGOUT_EVENT not in events:
        raise LogoutTokenValidationException(
            "Logout token 'events' claim must contain the "
            f"'{BACKCHANNEL_LOGOUT_EVENT}' member",
            token_part="payload",
        )


__all__ = [
    "BACKCHANNEL_LOGOUT_EVENT",
    "LOGOUT_TOKEN_PARAM",
    "validate_logout_token_claims",
]
