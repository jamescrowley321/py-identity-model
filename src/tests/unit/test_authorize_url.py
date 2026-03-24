"""Unit tests for authorization URL builder."""

from urllib.parse import parse_qs, urlparse

import pytest

from py_identity_model.core.authorize_url import build_authorization_url


AUTHZ_ENDPOINT = "https://auth.example.com/authorize"


@pytest.mark.unit
class TestBuildAuthorizationUrl:
    def test_basic_url(self):
        url = build_authorization_url(
            AUTHZ_ENDPOINT, client_id="app1", redirect_uri="https://app.com/cb"
        )
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        assert parsed.scheme == "https"
        assert params["client_id"] == ["app1"]
        assert params["redirect_uri"] == ["https://app.com/cb"]
        assert params["response_type"] == ["code"]
        assert params["scope"] == ["openid"]

    def test_pkce_params(self):
        url = build_authorization_url(
            AUTHZ_ENDPOINT,
            client_id="app1",
            redirect_uri="https://app.com/cb",
            code_challenge="challenge123",
            code_challenge_method="S256",
        )
        params = parse_qs(urlparse(url).query)

        assert params["code_challenge"] == ["challenge123"]
        assert params["code_challenge_method"] == ["S256"]

    def test_state_and_nonce(self):
        url = build_authorization_url(
            AUTHZ_ENDPOINT,
            client_id="app1",
            redirect_uri="https://app.com/cb",
            state="csrf_token",
            nonce="replay_nonce",
        )
        params = parse_qs(urlparse(url).query)

        assert params["state"] == ["csrf_token"]
        assert params["nonce"] == ["replay_nonce"]

    def test_custom_scope(self):
        url = build_authorization_url(
            AUTHZ_ENDPOINT,
            client_id="app1",
            redirect_uri="https://app.com/cb",
            scope="openid profile email",
        )
        params = parse_qs(urlparse(url).query)
        assert params["scope"] == ["openid profile email"]

    def test_extra_params(self):
        url = build_authorization_url(
            AUTHZ_ENDPOINT,
            client_id="app1",
            redirect_uri="https://app.com/cb",
            login_hint="user@example.com",
        )
        params = parse_qs(urlparse(url).query)
        assert params["login_hint"] == ["user@example.com"]

    def test_endpoint_with_existing_query(self):
        url = build_authorization_url(
            "https://auth.example.com/authorize?tenant=abc",
            client_id="app1",
            redirect_uri="https://app.com/cb",
        )
        assert "?tenant=abc&" in url

    def test_omitted_optional_params(self):
        url = build_authorization_url(
            AUTHZ_ENDPOINT,
            client_id="app1",
            redirect_uri="https://app.com/cb",
        )
        params = parse_qs(urlparse(url).query)
        assert "state" not in params
        assert "nonce" not in params
        assert "code_challenge" not in params
