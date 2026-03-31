"""Integration tests for Token Exchange (RFC 8693)."""

import pytest

from py_identity_model import (
    BaseRequest,
    FailedResponseAccessError,
    TokenExchangeRequest,
    TokenExchangeResponse,
)
from py_identity_model.core import token_type
from py_identity_model.core.token_exchange_logic import (
    prepare_token_exchange_request_data,
)


@pytest.mark.integration
class TestTokenExchangeIntegration:
    def test_request_model(self):
        req = TokenExchangeRequest(
            address="https://auth.example.com/token",
            client_id="svc",
            subject_token="user-access-token",
            subject_token_type=token_type.ACCESS_TOKEN,
        )
        assert isinstance(req, BaseRequest)
        assert req.subject_token_type == token_type.ACCESS_TOKEN
        assert req.actor_token is None

    def test_request_with_delegation(self):
        req = TokenExchangeRequest(
            address="https://auth.example.com/token",
            client_id="svc-a",
            subject_token="user-token",
            subject_token_type=token_type.ACCESS_TOKEN,
            actor_token="svc-a-token",
            actor_token_type=token_type.JWT,
        )
        assert req.actor_token == "svc-a-token"
        assert req.actor_token_type == token_type.JWT

    def test_response_guarded_fields(self):
        resp = TokenExchangeResponse(
            is_successful=False,
            error="invalid_grant",
        )
        with pytest.raises(FailedResponseAccessError):
            _ = resp.token
        with pytest.raises(FailedResponseAccessError):
            _ = resp.issued_token_type

    def test_response_success(self):
        resp = TokenExchangeResponse(
            is_successful=True,
            token={"access_token": "new-tok", "token_type": "Bearer"},
            issued_token_type=token_type.ACCESS_TOKEN,
        )
        assert resp.token is not None
        assert resp.token["access_token"] == "new-tok"
        assert resp.issued_token_type == token_type.ACCESS_TOKEN

    def test_prepare_request_data_impersonation(self):
        req = TokenExchangeRequest(
            address="https://auth.example.com/token",
            client_id="svc",
            subject_token="user-tok",
            subject_token_type=token_type.ACCESS_TOKEN,
        )
        data, _headers, auth = prepare_token_exchange_request_data(req)
        assert data["grant_type"] == "urn:ietf:params:oauth:grant-type:token-exchange"
        assert data["subject_token"] == "user-tok"
        assert data["subject_token_type"] == token_type.ACCESS_TOKEN
        assert data["client_id"] == "svc"
        assert "actor_token" not in data
        assert auth is None

    def test_prepare_request_data_delegation(self):
        req = TokenExchangeRequest(
            address="https://auth.example.com/token",
            client_id="svc-a",
            subject_token="user-tok",
            subject_token_type=token_type.ACCESS_TOKEN,
            actor_token="svc-tok",
            actor_token_type=token_type.JWT,
            client_secret="secret",
        )
        data, _headers, auth = prepare_token_exchange_request_data(req)
        assert data["actor_token"] == "svc-tok"
        assert data["actor_token_type"] == token_type.JWT
        assert auth == ("svc-a", "secret")

    def test_prepare_request_data_all_optional(self):
        req = TokenExchangeRequest(
            address="https://auth.example.com/token",
            client_id="svc",
            subject_token="user-tok",
            subject_token_type=token_type.ACCESS_TOKEN,
            resource="https://api.example.com",
            audience="api-service",
            scope="read write",
            requested_token_type=token_type.ID_TOKEN,
        )
        data, _headers, _auth = prepare_token_exchange_request_data(req)
        assert data["resource"] == "https://api.example.com"
        assert data["audience"] == "api-service"
        assert data["scope"] == "read write"
        assert data["requested_token_type"] == token_type.ID_TOKEN

    def test_token_type_constants(self):
        assert token_type.ACCESS_TOKEN.startswith("urn:ietf:params:oauth:")
        assert token_type.REFRESH_TOKEN.startswith("urn:ietf:params:oauth:")
        assert token_type.ID_TOKEN.startswith("urn:ietf:params:oauth:")
        assert token_type.SAML1.startswith("urn:ietf:params:oauth:")
        assert token_type.SAML2.startswith("urn:ietf:params:oauth:")
        assert token_type.JWT.startswith("urn:ietf:params:oauth:")
