"""Forged / negative token corpus for the token-blaster harness (TH-1.1).

Real OPs will not emit invalid tokens and node-oidc's keys are ephemeral and
not exported, so the negative corpus is forged off the *known* signing key of
the controllable :class:`~mock_op.MockOP` (design §3).

Each :class:`ForgedToken` records ``library_rejects`` — whether
:func:`py_identity_model.aio.validate_token` (signature + ``iss``/``aud``/``exp``
checks) rejects it. Note the distinction from *resource-server* policy, which
is T302's concern:

* ``id_as_access`` and ``cnf_bound`` are *validly signed JWTs for the audience*
  — the library ACCEPTS them; only the RS access-token marker / ``require_scope``
  layer (F-07 / F-02) distinguishes them. They therefore carry
  ``library_rejects=False`` here.
* ``oversized`` / ``multi_aud_untrusted`` are likewise valid to the library.

Real-issuer negatives that cannot be forged (a real OP signing an expired token
with its real key) reuse the committed expired tokens + cross-provider
``kid``-mismatch already in the integration suite.
"""

from __future__ import annotations

from dataclasses import dataclass
import time
from typing import TYPE_CHECKING, Any

import jwt


if TYPE_CHECKING:
    from .mock_op import MockOP


CORPUS_AUDIENCE = "mock-api"


@dataclass(frozen=True)
class ForgedToken:
    """A single corpus entry.

    Attributes:
        name: Stable class name (matches a :class:`~token_source.Malform` value).
        jwt: The compact-serialized token.
        description: What makes it invalid (or, for accepted classes, why the
            library accepts it despite RS-layer policy rejecting it).
        library_rejects: Whether ``aio.validate_token`` rejects it outright.
    """

    name: str
    jwt: str
    description: str
    library_rejects: bool


def _base_claims(mock_op: MockOP, now: int, *, audience: Any = CORPUS_AUDIENCE) -> dict:
    return {
        "iss": mock_op.issuer,
        "sub": "mock-subject",
        "aud": audience,
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "client_id": "mock-client",
        "scope": "read",
    }


def _tamper_signature(token: str) -> str:
    """Flip the *first* character of the signature segment (invalid signature).

    The first base64url character carries fully-significant bits, so flipping it
    always changes the decoded signature bytes. (The *last* character of an
    RSA-2048 signature encodes only 2 significant bits plus 4 discard bits, so
    flipping it can decode to identical bytes and leave the signature valid.)
    """
    header, payload, signature = token.split(".")
    flipped = "B" if signature[0] != "B" else "C"
    return f"{header}.{payload}.{flipped}{signature[1:]}"


def build_corpus(mock_op: MockOP) -> dict[str, ForgedToken]:
    """Build the full forged corpus keyed to *mock_op*'s known signing key."""
    now = int(time.time())
    entries: list[ForgedToken] = []

    def add(name: str, token: str, description: str, *, rejects: bool) -> None:
        entries.append(ForgedToken(name, token, description, rejects))

    # -- Accepted by the library (signature + iss + aud + exp all valid) -----
    add(
        "valid",
        mock_op.sign(_base_claims(mock_op, now)),
        "well-formed token signed by a published key",
        rejects=False,
    )
    id_claims = _base_claims(mock_op, now)
    id_claims.pop("scope")
    id_claims.pop("client_id")
    id_claims["nonce"] = "n-abc"
    add(
        "id_as_access",
        mock_op.sign(id_claims),
        "ID-token-shaped (no scope/client_id) presented as a bearer access "
        "token — library accepts; RS marker (F-07) must reject",
        rejects=False,
    )
    cnf_claims = _base_claims(mock_op, now)
    cnf_claims["cnf"] = {"jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"}
    add(
        "cnf_bound",
        mock_op.sign(cnf_claims),
        "DPoP/mTLS cnf-bound token presented as a plain bearer — library "
        "accepts (F-02 accepted-today contract; do not assume rejection)",
        rejects=False,
    )
    big_claims = _base_claims(mock_op, now)
    for i in range(200):
        big_claims[f"pad_{i}"] = "x" * 64
    add(
        "oversized",
        mock_op.sign(big_claims),
        "valid token bloated with 200 padding claims (resource-exhaustion probe)",
        rejects=False,
    )
    multi_aud = _base_claims(mock_op, now, audience=[CORPUS_AUDIENCE, "urn:untrusted"])
    add(
        "multi_aud_untrusted",
        mock_op.sign(multi_aud),
        "multi-aud token whose secondary audience is untrusted — library "
        "accepts because the trusted audience is present",
        rejects=False,
    )

    # -- Rejected by the library --------------------------------------------
    expired = _base_claims(mock_op, now)
    expired["iat"] = expired["nbf"] = now - 600
    expired["exp"] = now - 300
    add("expired", mock_op.sign(expired), "exp in the past", rejects=True)

    nbf_future = _base_claims(mock_op, now)
    nbf_future["nbf"] = now + 3600
    add("nbf_future", mock_op.sign(nbf_future), "nbf in the future", rejects=True)

    wrong_iss = _base_claims(mock_op, now)
    wrong_iss["iss"] = "https://evil.example.com"
    add(
        "wrong_iss",
        mock_op.sign(wrong_iss),
        "iss does not match discovery",
        rejects=True,
    )

    wrong_aud = _base_claims(mock_op, now, audience="urn:some-other-api")
    add(
        "wrong_aud",
        mock_op.sign(wrong_aud),
        "aud does not match expected",
        rejects=True,
    )

    add(
        "tampered_sig",
        _tamper_signature(mock_op.sign(_base_claims(mock_op, now))),
        "byte-flipped signature",
        rejects=True,
    )
    add(
        "unknown_kid",
        mock_op.sign(_base_claims(mock_op, now), key=mock_op.unpublished_key),
        "signed by a key whose kid is absent from JWKS",
        rejects=True,
    )
    add(
        "wrong_alg",
        jwt.encode(
            _base_claims(mock_op, now),
            # >= 32 bytes to avoid PyJWT's InsecureKeyLengthWarning; the exact
            # secret is irrelevant — the point is HS256 against an RSA kid.
            "harness-hmac-confusion-secret-key-32b",
            algorithm="HS256",
            headers={"kid": mock_op.primary_key.kid},
        ),
        "HS256 signed while claiming an RSA kid (alg-confusion)",
        rejects=True,
    )
    add(
        "alg_none",
        jwt.encode(_base_claims(mock_op, now), "", algorithm="none"),
        "unsigned token with alg:none",
        rejects=True,
    )
    return {entry.name: entry for entry in entries}
