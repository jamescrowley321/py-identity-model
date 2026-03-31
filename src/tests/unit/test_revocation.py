"""Unit tests for OAuth 2.0 Token Revocation (RFC 7009)."""

import httpx
import pytest
import respx

from py_identity_model import (
    BaseRequest,
    BaseResponse,
    TokenRevocationRequest,
    TokenRevocationResponse,
)
from py_identity_model.sync.revocation import revoke_token


REVOKE_URL = "https://auth.example.com/revoke"


@pytest.mark.unit
class TestRevocation:
    @respx.mock
    def test_successful_revocation(self):
        respx.post(REVOKE_URL).mock(return_value=httpx.Response(200))

        response = revoke_token(
            TokenRevocationRequest(
                address=REVOKE_URL,
                token="access_token_to_revoke",
                client_id="app1",
                client_secret="secret",
            )
        )

        assert response.is_successful is True

    @respx.mock
    def test_revocation_with_token_type_hint(self):
        respx.post(REVOKE_URL).mock(return_value=httpx.Response(200))

        response = revoke_token(
            TokenRevocationRequest(
                address=REVOKE_URL,
                token="refresh_token_to_revoke",
                client_id="app1",
                client_secret="secret",
                token_type_hint="refresh_token",
            )
        )

        assert response.is_successful is True

    @respx.mock
    def test_revocation_error(self):
        respx.post(REVOKE_URL).mock(
            return_value=httpx.Response(401, content=b"Unauthorized")
        )

        response = revoke_token(
            TokenRevocationRequest(
                address=REVOKE_URL,
                token="token",
                client_id="app1",
                client_secret="wrong",
            )
        )

        assert response.is_successful is False
        assert response.error is not None

    @respx.mock
    def test_public_client_revocation(self):
        respx.post(REVOKE_URL).mock(return_value=httpx.Response(200))

        response = revoke_token(
            TokenRevocationRequest(
                address=REVOKE_URL,
                token="token",
                client_id="public_app",
            )
        )

        assert response.is_successful is True

    @respx.mock
    def test_network_error(self):
        respx.post(REVOKE_URL).mock(
            side_effect=httpx.ConnectError("Connection refused")
        )

        response = revoke_token(
            TokenRevocationRequest(
                address=REVOKE_URL,
                token="token",
                client_id="app1",
                client_secret="secret",
            )
        )

        assert response.is_successful is False
        assert response.error is not None
        assert "Connection refused" in response.error

    def test_request_inherits_base(self):
        req = TokenRevocationRequest(address=REVOKE_URL, token="tok", client_id="app")
        assert isinstance(req, BaseRequest)

    def test_response_inherits_base(self):
        resp = TokenRevocationResponse(is_successful=True)
        assert isinstance(resp, BaseResponse)

    def test_response_has_no_guarded_fields(self):
        """Revocation response has no data fields to guard."""
        resp = TokenRevocationResponse(is_successful=True)
        assert resp.is_successful is True

    def test_failed_response_repr_does_not_crash(self):
        resp = TokenRevocationResponse(is_successful=False, error="fail")
        text = repr(resp)
        assert "TokenRevocationResponse" in text

    def test_failed_response_eq_does_not_crash(self):
        resp1 = TokenRevocationResponse(is_successful=False, error="fail")
        resp2 = TokenRevocationResponse(is_successful=False, error="fail")
        # Should not raise FailedResponseAccessError
        assert resp1 is not resp2

    @respx.mock
    def test_confidential_client_uses_basic_auth(self):
        """RFC 7009: Confidential clients authenticate via HTTP Basic."""
        route = respx.post(REVOKE_URL).mock(return_value=httpx.Response(200))

        revoke_token(
            TokenRevocationRequest(
                address=REVOKE_URL,
                token="tok",
                client_id="app1",
                client_secret="secret",
            )
        )

        request = route.calls[0].request
        assert request.headers.get("authorization") is not None
        assert request.headers["authorization"].startswith("Basic ")
        assert "client_id" not in request.content.decode()

    @respx.mock
    def test_public_client_sends_client_id_in_body(self):
        """RFC 7009: Public clients send client_id in POST body."""
        route = respx.post(REVOKE_URL).mock(return_value=httpx.Response(200))

        revoke_token(
            TokenRevocationRequest(
                address=REVOKE_URL,
                token="tok",
                client_id="public_app",
            )
        )

        request = route.calls[0].request
        body = request.content.decode()
        assert "client_id=public_app" in body
        assert request.headers.get("authorization") is None

    @respx.mock
    def test_token_type_hint_sent_in_body(self):
        """RFC 7009: token_type_hint included in POST body when provided."""
        route = respx.post(REVOKE_URL).mock(return_value=httpx.Response(200))

        revoke_token(
            TokenRevocationRequest(
                address=REVOKE_URL,
                token="tok",
                client_id="app1",
                client_secret="secret",
                token_type_hint="refresh_token",
            )
        )

        request = route.calls[0].request
        body = request.content.decode()
        assert "token_type_hint=refresh_token" in body

    @respx.mock
    def test_content_type_header(self):
        """RFC 7009: Revocation uses form-urlencoded content type."""
        route = respx.post(REVOKE_URL).mock(return_value=httpx.Response(200))

        revoke_token(
            TokenRevocationRequest(
                address=REVOKE_URL,
                token="tok",
                client_id="app1",
                client_secret="secret",
            )
        )

        request = route.calls[0].request
        assert request.headers["content-type"] == "application/x-www-form-urlencoded"

    @respx.mock
    def test_unexpected_error_returns_error_response(self):
        """Non-RequestError exceptions are caught and returned as error responses."""
        respx.post(REVOKE_URL).mock(side_effect=RuntimeError("unexpected"))

        response = revoke_token(
            TokenRevocationRequest(
                address=REVOKE_URL,
                token="tok",
                client_id="app1",
                client_secret="secret",
            )
        )

        assert response.is_successful is False
        assert response.error is not None
        assert "unexpected" in response.error

    @respx.mock
    def test_whitespace_client_secret_uses_public_client_flow(self):
        """Whitespace-only client_secret should use public client flow."""
        route = respx.post(REVOKE_URL).mock(return_value=httpx.Response(200))

        revoke_token(
            TokenRevocationRequest(
                address=REVOKE_URL,
                token="tok",
                client_id="app1",
                client_secret="   ",
            )
        )

        request = route.calls[0].request
        body = request.content.decode()
        assert "client_id=app1" in body
        assert request.headers.get("authorization") is None

    @respx.mock
    def test_empty_client_secret_uses_public_client_flow(self):
        """Empty client_secret should use public client flow, not Basic auth."""
        route = respx.post(REVOKE_URL).mock(return_value=httpx.Response(200))

        revoke_token(
            TokenRevocationRequest(
                address=REVOKE_URL,
                token="tok",
                client_id="app1",
                client_secret="",
            )
        )

        request = route.calls[0].request
        body = request.content.decode()
        assert "client_id=app1" in body
        assert request.headers.get("authorization") is None
