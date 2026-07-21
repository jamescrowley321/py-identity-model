"""Unit tests for the RP-Initiated Logout end-session URL builder.

Covers OpenID Connect RP-Initiated Logout 1.0 §2 (LOGOUT-001, LOGOUT-002).
"""

from urllib.parse import parse_qs, urlparse

import pytest

from py_identity_model import build_end_session_url as build_end_session_url_top
from py_identity_model.aio import (
    build_end_session_url as build_end_session_url_aio,
)
from py_identity_model.core.logout_logic import build_end_session_url
from py_identity_model.sync import (
    build_end_session_url as build_end_session_url_sync,
)


END_SESSION_ENDPOINT = "https://op.example.com/logout"


@pytest.mark.unit
class TestBuildEndSessionUrl:
    def test_all_params(self):
        # LOGOUT-001: end-session URL with all RP-Initiated Logout params.
        url = build_end_session_url(
            END_SESSION_ENDPOINT,
            id_token_hint="header.payload.sig",
            client_id="app1",
            post_logout_redirect_uri="https://app.com/post-logout",
            state="csrf_token",
        )
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        assert parsed.scheme == "https"
        assert parsed.netloc == "op.example.com"
        assert parsed.path == "/logout"
        assert params["id_token_hint"] == ["header.payload.sig"]
        assert params["client_id"] == ["app1"]
        assert params["post_logout_redirect_uri"] == ["https://app.com/post-logout"]
        assert params["state"] == ["csrf_token"]

    def test_id_token_hint_only(self):
        # LOGOUT-002: end-session URL with only id_token_hint; nothing else.
        url = build_end_session_url(
            END_SESSION_ENDPOINT,
            id_token_hint="header.payload.sig",
        )
        params = parse_qs(urlparse(url).query)

        assert params["id_token_hint"] == ["header.payload.sig"]
        assert "client_id" not in params
        assert "post_logout_redirect_uri" not in params
        assert "state" not in params

    def test_no_params_returns_bare_endpoint(self):
        # Every RP-Initiated Logout param is optional (§2): no params -> no "?".
        url = build_end_session_url(END_SESSION_ENDPOINT)
        assert url == END_SESSION_ENDPOINT

    def test_logout_hint_and_ui_locales(self):
        url = build_end_session_url(
            END_SESSION_ENDPOINT,
            logout_hint="user@example.com",
            ui_locales="en-US fr-CA",
        )
        params = parse_qs(urlparse(url).query)

        assert params["logout_hint"] == ["user@example.com"]
        assert params["ui_locales"] == ["en-US fr-CA"]

    def test_extra_params_passthrough(self):
        url = build_end_session_url(
            END_SESSION_ENDPOINT,
            id_token_hint="tok",
            custom="value",
        )
        params = parse_qs(urlparse(url).query)

        assert params["custom"] == ["value"]

    def test_empty_endpoint_raises(self):
        with pytest.raises(ValueError, match="must not be empty"):
            build_end_session_url("", id_token_hint="tok")

    def test_whitespace_endpoint_raises(self):
        with pytest.raises(ValueError, match="must not be empty"):
            build_end_session_url("   ", id_token_hint="tok")

    def test_fragment_stripped(self):
        url = build_end_session_url(
            f"{END_SESSION_ENDPOINT}#frag",
            state="s",
        )
        parsed = urlparse(url)
        assert parsed.fragment == ""
        assert parse_qs(parsed.query)["state"] == ["s"]

    def test_existing_query_uses_ampersand_separator(self):
        url = build_end_session_url(
            f"{END_SESSION_ENDPOINT}?foo=bar",
            state="s",
        )
        params = parse_qs(urlparse(url).query)

        assert params["foo"] == ["bar"]
        assert params["state"] == ["s"]

    def test_public_export_identity(self):
        # Same pure function is exported from every surface (sync/aio parity).
        assert build_end_session_url_top is build_end_session_url
        assert build_end_session_url_sync is build_end_session_url
        assert build_end_session_url_aio is build_end_session_url
