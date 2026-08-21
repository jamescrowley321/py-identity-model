"""Adversarial subject-presence test for ID tokens (R.10 / SC5).

The R.10 control ("require ``sub`` on ID tokens") is only partially present:
``decode_and_validate_jwt`` compares ``sub`` ONLY when the caller pins a
``subject`` (``jwt_helpers.py``). When no subject is pinned, an ID token with
no ``sub`` — or an empty ``sub`` — is accepted, even though ``sub`` is REQUIRED
in an ID token (OIDC Core 2). Since ``sub`` is the identity anchor, a missing
one yields a validated principal with no subject.

These tests validate a signed ID token that omits / empties ``sub`` and assert
rejection. They XFAIL until subject presence is enforced for ID tokens.
"""

import pytest

from py_identity_model.core.models import TokenValidationConfig
from py_identity_model.exceptions import TokenValidationException
from py_identity_model.sync.token_validation import validate_token

from ._security_helpers import generate_rsa_keypair, sign_jwt


pytestmark = pytest.mark.unit

ISSUER = "https://idp.example.com"


def _validate(claims: dict) -> None:
    key_dict, pem = generate_rsa_keypair()
    token = sign_jwt(pem, {"iss": ISSUER, **claims})
    config = TokenValidationConfig(
        perform_disco=False,
        key=key_dict,
        algorithms=["RS256"],
        issuer=ISSUER,
    )
    validate_token(jwt=token, token_validation_config=config)


@pytest.mark.xfail(
    strict=True,
    reason="R.10/SC5: sub is only checked when a subject is pinned; an ID token "
    "with no sub is accepted",
)
def test_id_token_without_sub_is_rejected() -> None:
    with pytest.raises(TokenValidationException):
        _validate({})  # no sub claim at all


@pytest.mark.xfail(
    strict=True,
    reason="R.10/SC5: an ID token with an empty sub is accepted (sub presence "
    "not enforced)",
)
def test_id_token_with_empty_sub_is_rejected() -> None:
    with pytest.raises(TokenValidationException):
        _validate({"sub": ""})
