"""Fail-closed control test: HTTP Basic client-auth credential encoding.

Seed test for the security-gate foundation (Epic 19 G.1). It proves an
already-shipped control — RFC 6749 §2.3.1 form-urlencoding of Basic-auth
credentials in ``core.client_auth.basic_auth_credentials`` (#482) — and is
written so that deleting or weakening that control leaves a **surviving
mutant** that ``make mutation-security`` catches.

The control matters because an authorization server that form-urldecodes the
Basic-auth username/password per spec would mangle a ``client_id`` or secret
containing reserved characters (``%``, ``+``, ``/``, ``:``, space). If the
``quote(..., safe="")`` control is removed, those characters are sent verbatim
and authentication silently fails — or, worse, a ``:`` in a secret splits the
credential and changes the authenticated identity.
"""

import pytest

from py_identity_model.core.client_auth import basic_auth_credentials


@pytest.mark.unit
class TestBasicAuthEncoding:
    """Every reserved character MUST be percent-encoded before Basic auth."""

    def test_colon_in_secret_is_escaped(self) -> None:
        # A ``:`` in the secret must be escaped so it cannot be mistaken for
        # the Basic-auth ``user:pass`` separator by a spec-compliant server.
        _, secret = basic_auth_credentials("client", "pa:ss")
        assert secret == "pa%3Ass"
        assert ":" not in secret

    def test_percent_and_plus_and_slash_are_escaped(self) -> None:
        # Reserved characters must be escaped in BOTH the client_id and the
        # secret. Asserting ``/`` in the secret (not just the id) pins the
        # empty ``safe`` set: the PyJWT/urllib default (``safe="/"``) would
        # leave ``/`` unescaped, so this kills that downgrade mutant.
        client_id, secret = basic_auth_credentials("cl+id/x", "se%cr/et")
        assert client_id == "cl%2Bid%2Fx"
        assert secret == "se%25cr%2Fet"

    def test_space_is_escaped_not_dropped(self) -> None:
        client_id, _ = basic_auth_credentials("a b", "secret")
        # ``quote`` with an empty safe set encodes space as ``%20`` (never
        # ``+``, which is form-body specific and would be misdecoded here).
        assert client_id == "a%20b"

    def test_clean_ascii_passes_through_unchanged(self) -> None:
        # The control must be a no-op for the common case, otherwise it would
        # break every existing clean credential.
        client_id, secret = basic_auth_credentials("my-client", "s3cr3t.value~1")
        assert client_id == "my-client"
        assert secret == "s3cr3t.value~1"
