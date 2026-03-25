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

    def test_request_inherits_base(self):
        req = TokenRevocationRequest(
            address=REVOKE_URL, token="tok", client_id="app"
        )
        assert isinstance(req, BaseRequest)

    def test_response_inherits_base(self):
        resp = TokenRevocationResponse(is_successful=True)
        assert isinstance(resp, BaseResponse)

    def test_response_has_no_guarded_fields(self):
        """Revocation response has no data fields to guard."""
        resp = TokenRevocationResponse(is_successful=True)
        assert resp.is_successful is True
