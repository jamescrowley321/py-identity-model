"""Token characterization harness for the F-07 discriminator decision.

Data-gathering only. This test mints REAL tokens against whatever provider the
``--env-file`` selects and tabulates the JOSE-header + claim fields that could
serve as a *positive* access-token signal, so the owner can pick a safe
discriminator for the F-07 fix (ID-token-accepted-as-access-token).

The current FastAPI middleware rejects an ID-token-used-as-access-token only via
a NEGATIVE heuristic (presence of ``nonce``/``at_hash``/``c_hash``), which fails
because those claims are OPTIONAL in the auth-code flow. The fix must instead
REQUIRE a positive access-token signal, but which signal is safe depends on how
each OP issues tokens. This harness records, per provider, the access-token vs
ID-token values of: header ``typ``/``alg``; claims ``aud`` (and whether it
equals the client_id), ``iss``, ``sub``, ``scope``/``scp``, ``client_id``,
``azp``, ``nonce``, ``at_hash``, ``c_hash``, ``exp``, ``iat``.

It RECORDS; it asserts only that a real access token and a real ID token were
obtained. Decoding is WITHOUT signature verification (we only read fields).

Run against node-oidc locally (clear the stale token/JWKS caches first)::

    rm -f /tmp/pytest-of-*/node-oidc_*.json
    make test-integration-node-oidc

To see the printed comparison table, bring the fixture up the way the Makefile
target does (``docker compose -f infra/node-oidc-provider/... up``) then::

    uv run pytest src/tests/integration/test_token_characterization.py \
        -m integration --env-file=.env.node-oidc -s -v

Point ``--env-file`` at any ``.env.<provider>`` (Descope/Keycloak/Ory) to
characterize that IdP; the comparison table is also written to
``token_characterization_<provider_slug>.md`` in the working directory.
"""

import os
from pathlib import Path

import jwt as pyjwt
import pytest


# A JWT has exactly three dot-separated segments (two separators). Opaque
# access tokens (e.g. random reference strings) will not match and are recorded
# as ``opaque`` rather than decoded.
JWT_SEPARATOR_COUNT = 2

# JOSE-header fields worth comparing between an access token and an ID token.
_HEADER_FIELDS = ("typ", "alg", "kid")

# Claim fields worth comparing. These are exactly the candidate discriminators
# named in the F-07 investigation.
_CLAIM_FIELDS = (
    "iss",
    "sub",
    "aud",
    "azp",
    "client_id",
    "scope",
    "scp",
    "nonce",
    "at_hash",
    "c_hash",
    "exp",
    "iat",
)


def _looks_like_jwt(token: str) -> bool:
    """Whether ``token`` is a three-segment JWS (all segments non-empty)."""
    return token.count(".") == JWT_SEPARATOR_COUNT and all(token.split("."))


def _characterize(token: str) -> dict:
    """Decode ``token`` WITHOUT signature verification and pull comparison fields.

    Returns a flat ``{field: value}`` mapping. Header fields are prefixed
    ``header.``; claim fields use their bare name. Opaque (non-JWT) tokens
    report only ``format`` so the table still renders a column for them.
    """
    if not _looks_like_jwt(token):
        return {"format": "opaque"}
    header = pyjwt.get_unverified_header(token)
    claims = pyjwt.decode(token, options={"verify_signature": False})
    record: dict = {"format": "jwt"}
    for field in _HEADER_FIELDS:
        record[f"header.{field}"] = header.get(field)
    for field in _CLAIM_FIELDS:
        record[field] = claims.get(field)
    return record


def _fmt_value(value: object) -> str:
    """Render a raw field value, marking absence explicitly."""
    if value is None:
        return "(absent)"
    return repr(value)


def _fmt_present(value: object) -> str:
    """Render a present/absent field, echoing the value when present."""
    if value is None:
        return "no"
    return f"yes ({value!r})"


def _aud_matches_client(record: dict, known_client_id: str) -> str:
    """Whether the token's ``aud`` equals the client_id.

    Prefers the token's own ``client_id`` claim (present on RFC 9068 access
    tokens); falls back to the known client_id used to obtain the token (ID
    tokens have no ``client_id`` claim — their audience *is* the client).
    """
    aud = record.get("aud")
    if aud is None:
        return "(no aud)"
    client_id = record.get("client_id") or known_client_id
    if isinstance(aud, list):
        return "yes" if client_id in aud else "no"
    return "yes" if aud == client_id else "no"


# (row label, record key, single-value formatter). The derived
# ``aud == client_id?`` row is inserted after ``aud`` by ``_render_full_table``.
_VALUE_ROWS = (
    ("format", "format", lambda v: str(v) if v is not None else "?"),
    ("header.typ", "header.typ", _fmt_value),
    ("header.alg", "header.alg", _fmt_value),
    ("header.kid", "header.kid", _fmt_value),
    ("iss", "iss", _fmt_value),
    ("sub", "sub", _fmt_value),
    ("aud", "aud", _fmt_value),
    ("azp", "azp", _fmt_value),
    ("client_id (claim present?)", "client_id", _fmt_present),
    ("scope (claim present?)", "scope", _fmt_present),
    ("scp (claim present?)", "scp", _fmt_present),
    ("nonce (present?)", "nonce", _fmt_present),
    ("at_hash (present?)", "at_hash", _fmt_present),
    ("c_hash (present?)", "c_hash", _fmt_present),
    ("exp", "exp", _fmt_value),
    ("iat", "iat", _fmt_value),
)


def _render_table(headers: list[str], rows: list[list[str]]) -> str:
    """Render an aligned Markdown pipe table (readable in stdout and as .md)."""
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def fmt_row(cells: list[str]) -> str:
        padded = [cell.ljust(widths[i]) for i, cell in enumerate(cells)]
        return "| " + " | ".join(padded) + " |"

    separator = "| " + " | ".join("-" * widths[i] for i in range(len(headers))) + " |"
    lines = [fmt_row(headers), separator]
    lines.extend(fmt_row(row) for row in rows)
    return "\n".join(lines)


def _render_full_table(columns: list[tuple[str, dict]], known_client_id: str) -> str:
    """Build the field-by-field comparison table for the given token columns."""
    titles = [title for title, _ in columns]
    records = [record for _, record in columns]
    headers = ["field", *titles]
    rows: list[list[str]] = []
    for label, key, formatter in _VALUE_ROWS:
        rows.append([label, *[formatter(record.get(key)) for record in records]])
        if key == "aud":
            rows.append(
                [
                    "aud == client_id?",
                    *[
                        _aud_matches_client(record, known_client_id)
                        for record in records
                    ],
                ]
            )
    return _render_table(headers, rows)


def _try_client_credentials_token(request) -> tuple[str | None, str | None]:
    """Best-effort client_credentials access token via the shared fixture.

    Returns ``(access_token, None)`` on success or ``(None, note)`` when the
    provider advertises client_credentials but the fetch could not be completed
    — recorded as a note rather than failing the whole characterization.
    """
    try:
        response = request.getfixturevalue("client_credentials_token")
    except pytest.fail.Exception as exc:
        return None, f"client_credentials fetch failed: {exc}"
    except pytest.skip.Exception as exc:
        return None, f"client_credentials skipped: {exc}"
    access_token = (response.token or {}).get("access_token")
    if not access_token:
        return None, "client_credentials response carried no access_token"
    return access_token, None


@pytest.mark.integration
class TestTokenCharacterization:
    """Tabulate what distinguishes a provider's access token from its ID token."""

    def test_characterize_access_vs_id_token(
        self,
        auth_code_result,
        test_config,
        provider_slug,
        provider_capabilities,
        request,
    ):
        """Mint real tokens and emit the access-vs-ID comparison table.

        The auth-code flow yields both the ID token and an access token; when
        the provider supports it, a client_credentials access token is added as
        a third column. Skips cleanly when no ID token is issued.
        """
        token_response = auth_code_result["token_response"]
        assert token_response.is_successful, (
            f"Auth-code token exchange failed: {token_response.error}"
        )
        token = token_response.token or {}
        id_token = token.get("id_token")
        ac_access_token = token.get("access_token")

        if not id_token:
            pytest.skip(
                "Auth-code token response carried no id_token "
                "(openid scope not honoured) — nothing to characterize"
            )
        assert ac_access_token, "Auth-code flow returned no access_token"
        assert _looks_like_jwt(id_token), "ID token is not a JWT — cannot decode"

        known_client_id = test_config.get("TEST_AUTH_CODE_CLIENT_ID", "")

        columns: list[tuple[str, dict]] = [
            ("ID Token", _characterize(id_token)),
            ("AC Access Token", _characterize(ac_access_token)),
        ]

        notes: list[str] = []
        if "client_credentials" in provider_capabilities:
            cc_access_token, note = _try_client_credentials_token(request)
            if cc_access_token:
                columns.append(("CC Access Token", _characterize(cc_access_token)))
            elif note:
                notes.append(note)
        else:
            notes.append(
                "Provider does not advertise client_credentials — CC column omitted."
            )

        table = _render_full_table(columns, known_client_id)

        header_line = f"# Token characterization — provider: {provider_slug}"
        legend = (
            "Columns: ID Token vs access token(s). AC = authorization_code flow, "
            "CC = client_credentials grant. Decoded WITHOUT signature "
            f"verification. known client_id (auth-code) = {known_client_id!r}.\n"
            "A row where the access-token column carries a value the ID-token "
            "column lacks (or vice-versa) is a candidate F-07 discriminator."
        )
        note_block = ""
        if notes:
            note_block = "\n\nNotes:\n" + "\n".join(f"- {n}" for n in notes)
        document = f"{header_line}\n\n{legend}\n\n{table}{note_block}\n"

        # Emit to stdout (visible with ``-s``) and persist next to the run.
        print("\n" + document)
        out_path = Path.cwd() / f"token_characterization_{provider_slug}.md"
        out_path.write_text(document)
        print(f"[token-characterization] table written to {out_path}")

        # In CI, pytest captures stdout on a passing test, so also append the
        # table to the GitHub Actions job summary (the .md is additionally
        # uploaded as a build artifact). This is how the data leaves CI.
        step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if step_summary:
            with Path(step_summary).open("a", encoding="utf-8") as fh:
                fh.write(document + "\n")

        # Minimum sanity only — this test RECORDS.
        assert id_token, "no id_token obtained"
        assert ac_access_token, "no access_token obtained"
