"""Live integration tests for OpenID Connect RP-Initiated Logout 1.0.

Exercises the end-session URL round-trip against a running provider: the RP
builds an end-session URL with ``build_end_session_url``, drives the user
agent through the OP's logout, and validates the ``state`` echoed back to the
post-logout redirect URI with ``validate_post_logout_state``.

Provider-agnostic and capability-gated — runs where the provider advertises an
``end_session_endpoint`` and supports the automated auth-code flow (Keycloak,
node-oidc), skips cleanly elsewhere. Constructor/URL-shape tests live in the
unit suite; this file only covers behaviour that needs a live OP.

Spec IDs: LOGOUT-001 (build end-session URL), LOGOUT-002 (state round-trip),
LOGOUT-003 (state mismatch rejected).
"""

from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from py_identity_model import (
    LogoutStateValidationException,
    build_end_session_url,
    validate_post_logout_state,
)


def _require_end_session(provider_capabilities):
    if "end_session" not in provider_capabilities:
        pytest.skip("Provider does not advertise end_session_endpoint")


@pytest.mark.integration
class TestRpInitiatedLogout:
    """RP-Initiated Logout end-session round-trip against a live provider."""

    def test_end_session_state_round_trip(
        self,
        provider_capabilities,
        discovery_document,
        test_config,
        logout_id_token,
    ):
        """End-session redirect echoes ``state`` back to the RP.

        LOGOUT-001: the RP builds the end-session URL from discovery.
        LOGOUT-002: the OP redirects to ``post_logout_redirect_uri`` with the
        ``state`` value round-tripped unchanged.
        """
        _require_end_session(provider_capabilities)
        end_session_endpoint = discovery_document.end_session_endpoint
        assert end_session_endpoint, "discovery missing end_session_endpoint"

        client_id = test_config["TEST_AUTH_CODE_CLIENT_ID"]
        redirect_uri = test_config["TEST_AUTH_CODE_REDIRECT_URI"]
        expected_state = "kc5-logout-state-round-trip"

        logout_url = build_end_session_url(
            end_session_endpoint=end_session_endpoint,
            id_token_hint=logout_id_token,
            client_id=client_id,
            post_logout_redirect_uri=redirect_uri,
            state=expected_state,
        )

        with httpx.Client(follow_redirects=True, timeout=10.0) as client:
            resp = client.get(logout_url)

        # A provider only completes the silent redirect when the id_token_hint
        # alone lets it honour the request without a browser session or user
        # interaction (Keycloak does; node-oidc interposes a 200 confirmation
        # page or rejects the sessionless request with 400). Neither the
        # interactive nor the rejected path can be driven headlessly, so skip
        # cleanly rather than fail — the OP simply does not support silent,
        # hint-only RP-initiated logout.
        landing = str(resp.url)
        if not _matches(landing, redirect_uri):
            pytest.skip(
                "Provider did not complete the silent logout redirect "
                f"(status {resp.status_code}, landed on {landing})"
            )

        returned_state = _query_param(landing, "state")
        # Valid round-trip: constant-time match must not raise (LOGOUT-002).
        validate_post_logout_state(expected_state, returned_state)

    def test_tampered_state_is_rejected(
        self,
        provider_capabilities,
        discovery_document,
        test_config,
        logout_id_token,
    ):
        """A mismatched ``state`` is rejected (LOGOUT-003).

        Drives the same live round-trip, then asserts the CSRF check fails
        when the RP's stored state differs from what came back.
        """
        _require_end_session(provider_capabilities)
        end_session_endpoint = discovery_document.end_session_endpoint
        assert end_session_endpoint, "discovery missing end_session_endpoint"

        redirect_uri = test_config["TEST_AUTH_CODE_REDIRECT_URI"]
        sent_state = "kc5-logout-state-tampered"

        logout_url = build_end_session_url(
            end_session_endpoint=end_session_endpoint,
            id_token_hint=logout_id_token,
            client_id=test_config["TEST_AUTH_CODE_CLIENT_ID"],
            post_logout_redirect_uri=redirect_uri,
            state=sent_state,
        )

        with httpx.Client(follow_redirects=True, timeout=10.0) as client:
            resp = client.get(logout_url)

        landing = str(resp.url)
        if not _matches(landing, redirect_uri):
            pytest.skip(
                "Provider did not complete the silent logout redirect "
                f"(landed on {landing})"
            )

        returned_state = _query_param(landing, "state")
        assert returned_state == sent_state, "provider did not echo state back"

        # RP's stored state differs from the returned value → reject.
        with pytest.raises(LogoutStateValidationException):
            validate_post_logout_state("a-different-stored-state", returned_state)


def _matches(url: str, redirect_uri: str) -> bool:
    """True when *url* shares scheme/host/port/path with *redirect_uri*."""
    a, b = urlparse(url), urlparse(redirect_uri)
    return (a.scheme, a.netloc, a.path) == (b.scheme, b.netloc, b.path)


def _query_param(url: str, name: str) -> str | None:
    values = parse_qs(urlparse(url).query).get(name)
    return values[0] if values else None
