"""Unit tests for Pushed Authorization Requests (RFC 9126)."""

import httpx
import pytest
import respx

from py_identity_model import (
    BaseRequest,
    BaseResponse,
    PushedAuthorizationRequest,
    PushedAuthorizationResponse,
)
from py_identity_model.sync.par import push_authorization_request


PAR_URL = "https://auth.example.com/par"
PAR_RESPONSE = {
    "request_uri": "urn:ietf:params:oauth:request_uri:abc123",
    "expires_in": 60,
}


@pytest.mark.unit
class TestPAR:
    @respx.mock
    def test_successful_par(self):
        respx.post(PAR_URL).mock(
            return_value=httpx.Response(201, json=PAR_RESPONSE)
        )
        response = push_authorization_request(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="app1",
                redirect_uri="https://app.com/cb",
                client_secret="secret",
            )
        )
        assert response.is_successful is True
        assert (
            response.request_uri == "urn:ietf:params:oauth:request_uri:abc123"
        )
        assert response.expires_in == 60

    @respx.mock
    def test_par_with_pkce(self):
        respx.post(PAR_URL).mock(
            return_value=httpx.Response(201, json=PAR_RESPONSE)
        )
        response = push_authorization_request(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="app1",
                redirect_uri="https://app.com/cb",
                code_challenge="challenge",
                code_challenge_method="S256",
            )
        )
        assert response.is_successful is True

    @respx.mock
    def test_par_error(self):
        respx.post(PAR_URL).mock(
            return_value=httpx.Response(
                400, content=b'{"error":"invalid_request"}'
            )
        )
        response = push_authorization_request(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="app1",
                redirect_uri="https://app.com/cb",
                client_secret="secret",
            )
        )
        assert response.is_successful is False

    def test_request_inherits_base(self):
        req = PushedAuthorizationRequest(
            address=PAR_URL, client_id="app", redirect_uri="https://app.com/cb"
        )
        assert isinstance(req, BaseRequest)

    def test_response_inherits_base(self):
        resp = PushedAuthorizationResponse(
            is_successful=True, request_uri="urn:...", expires_in=60
        )
        assert isinstance(resp, BaseResponse)
