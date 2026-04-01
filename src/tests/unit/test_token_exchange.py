"""Unit tests for Token Exchange (RFC 8693)."""

import httpx
import pytest
import respx

from py_identity_model import (
    BaseRequest,
    BaseResponse,
    FailedResponseAccessError,
    TokenExchangeRequest,
    TokenExchangeResponse,
)
from py_identity_model.core import token_type
from py_identity_model.core.token_exchange_logic import (
    prepare_token_exchange_request_data,
)
from py_identity_model.core.token_type import ACCESS_TOKEN, ID_TOKEN, JWT
from py_identity_model.sync.token_exchange import exchange_token


TOKEN_URL = "https://auth.example.com/token"

TOKEN_EXCHANGE_RESPONSE = {
    "access_token": "eyJhbGci...",
    "issued_token_type": ACCESS_TOKEN,
    "token_type": "Bearer",
    "expires_in": 3600,
}


@pytest.mark.unit
class TestExchangeToken:
    @respx.mock
    def test_successful_impersonation(self):
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=TOKEN_EXCHANGE_RESPONSE)
        )
        response = exchange_token(
            TokenExchangeRequest(
                address=TOKEN_URL,
                client_id="service-a",
                subject_token="user-access-token",
                subject_token_type=ACCESS_TOKEN,
                client_secret="secret",
            )
        )
        assert response.is_successful is True
        assert response.token is not None
        assert response.token["access_token"] == "eyJhbGci..."
        assert response.issued_token_type == ACCESS_TOKEN

    @respx.mock
    def test_successful_delegation(self):
        delegation_response = {
            **TOKEN_EXCHANGE_RESPONSE,
            "issued_token_type": ACCESS_TOKEN,
        }
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=delegation_response)
        )
        response = exchange_token(
            TokenExchangeRequest(
                address=TOKEN_URL,
                client_id="service-a",
                subject_token="user-access-token",
                subject_token_type=ACCESS_TOKEN,
                actor_token="service-a-token",
                actor_token_type=JWT,
                client_secret="secret",
            )
        )
        assert response.is_successful is True
        assert response.token is not None

    @respx.mock
    def test_with_all_optional_params(self):
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=TOKEN_EXCHANGE_RESPONSE)
        )
        response = exchange_token(
            TokenExchangeRequest(
                address=TOKEN_URL,
                client_id="service-a",
                subject_token="user-token",
                subject_token_type=ACCESS_TOKEN,
                resource="https://api.example.com",
                audience="api-service",
                scope="read write",
                requested_token_type=ID_TOKEN,
                client_secret="secret",
            )
        )
        assert response.is_successful is True

    @respx.mock
    def test_error_response(self):
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                400,
                content=b'{"error":"invalid_grant","error_description":"Subject token expired"}',
            )
        )
        response = exchange_token(
            TokenExchangeRequest(
                address=TOKEN_URL,
                client_id="service-a",
                subject_token="expired-token",
                subject_token_type=ACCESS_TOKEN,
                client_secret="secret",
            )
        )
        assert response.is_successful is False

    @respx.mock
    def test_public_client(self):
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=TOKEN_EXCHANGE_RESPONSE)
        )
        response = exchange_token(
            TokenExchangeRequest(
                address=TOKEN_URL,
                client_id="public-app",
                subject_token="user-token",
                subject_token_type=ACCESS_TOKEN,
            )
        )
        assert response.is_successful is True

    def test_request_inherits_base(self):
        req = TokenExchangeRequest(
            address=TOKEN_URL,
            client_id="app",
            subject_token="tok",
            subject_token_type=ACCESS_TOKEN,
        )
        assert isinstance(req, BaseRequest)

    def test_response_inherits_base(self):
        resp = TokenExchangeResponse(
            is_successful=True,
            token={"access_token": "tok"},
            issued_token_type=ACCESS_TOKEN,
        )
        assert isinstance(resp, BaseResponse)

    @respx.mock
    def test_public_client_sends_client_id_in_body(self):
        """M1: Public clients send client_id in form body."""
        route = respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=TOKEN_EXCHANGE_RESPONSE)
        )
        exchange_token(
            TokenExchangeRequest(
                address=TOKEN_URL,
                client_id="public-app",
                subject_token="user-token",
                subject_token_type=ACCESS_TOKEN,
            )
        )
        request = route.calls[0].request
        body = request.content.decode()
        assert "client_id=public-app" in body

    @respx.mock
    def test_confidential_client_excludes_client_id_from_body(self):
        """M1: Confidential clients use Basic Auth, no client_id in body."""
        route = respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=TOKEN_EXCHANGE_RESPONSE)
        )
        exchange_token(
            TokenExchangeRequest(
                address=TOKEN_URL,
                client_id="service-a",
                subject_token="user-token",
                subject_token_type=ACCESS_TOKEN,
                client_secret="secret",
            )
        )
        request = route.calls[0].request
        body = request.content.decode()
        assert "client_id=" not in body
        assert request.headers.get("authorization") is not None

    def test_actor_token_without_type_returns_error(self):
        """M2: actor_token without actor_token_type returns error response."""
        response = exchange_token(
            TokenExchangeRequest(
                address=TOKEN_URL,
                client_id="service-a",
                subject_token="user-token",
                subject_token_type=ACCESS_TOKEN,
                actor_token="actor-token",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "actor_token_type is REQUIRED" in response.error

    def test_empty_subject_token_returns_error(self):
        """S2: Empty subject_token returns error response."""
        response = exchange_token(
            TokenExchangeRequest(
                address=TOKEN_URL,
                client_id="service-a",
                subject_token="",
                subject_token_type=ACCESS_TOKEN,
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "subject_token must not be empty" in response.error

    def test_empty_actor_token_returns_error(self):
        """S2: Empty actor_token returns error response."""
        response = exchange_token(
            TokenExchangeRequest(
                address=TOKEN_URL,
                client_id="service-a",
                subject_token="user-token",
                subject_token_type=ACCESS_TOKEN,
                actor_token="",
                actor_token_type=JWT,
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "actor_token must not be empty" in response.error

    def test_empty_actor_token_type_returns_error(self):
        """S2: Empty actor_token_type returns error response."""
        response = exchange_token(
            TokenExchangeRequest(
                address=TOKEN_URL,
                client_id="service-a",
                subject_token="user-token",
                subject_token_type=ACCESS_TOKEN,
                actor_token="actor-token",
                actor_token_type="",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "actor_token_type must not be empty" in response.error

    @respx.mock
    def test_empty_client_secret_treated_as_absent(self):
        """S2: Empty client_secret treated as public client."""
        route = respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=TOKEN_EXCHANGE_RESPONSE)
        )
        exchange_token(
            TokenExchangeRequest(
                address=TOKEN_URL,
                client_id="app",
                subject_token="tok",
                subject_token_type=ACCESS_TOKEN,
                client_secret="",
            )
        )
        request = route.calls[0].request
        body = request.content.decode()
        assert "client_id=app" in body
        assert request.headers.get("authorization") is None

    @respx.mock
    def test_non_json_success_returns_error(self):
        """S3: Non-JSON body on 200 returns error instead of crashing."""
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, content=b"<html>Gateway Error</html>")
        )
        response = exchange_token(
            TokenExchangeRequest(
                address=TOKEN_URL,
                client_id="service-a",
                subject_token="user-token",
                subject_token_type=ACCESS_TOKEN,
                client_secret="secret",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "invalid JSON" in response.error

    @respx.mock
    def test_non_dict_json_success_returns_error(self):
        """S3: Non-dict JSON on 200 returns error instead of AttributeError."""
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=["not", "a", "dict"])
        )
        response = exchange_token(
            TokenExchangeRequest(
                address=TOKEN_URL,
                client_id="service-a",
                subject_token="user-token",
                subject_token_type=ACCESS_TOKEN,
                client_secret="secret",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "not a JSON object" in response.error

    @respx.mock
    def test_network_error(self):
        respx.post(TOKEN_URL).mock(side_effect=httpx.ConnectError("Connection refused"))
        response = exchange_token(
            TokenExchangeRequest(
                address=TOKEN_URL,
                client_id="service-a",
                subject_token="user-token",
                subject_token_type=ACCESS_TOKEN,
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "Connection refused" in response.error

    @respx.mock
    def test_missing_access_token_returns_error(self):
        """BH M1: Success response missing access_token is rejected."""
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "token_type": "Bearer",
                    "issued_token_type": ACCESS_TOKEN,
                },
            )
        )
        response = exchange_token(
            TokenExchangeRequest(
                address=TOKEN_URL,
                client_id="service-a",
                subject_token="tok",
                subject_token_type=ACCESS_TOKEN,
                client_secret="secret",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "access_token" in response.error

    @respx.mock
    def test_missing_token_type_returns_error(self):
        """BH M1: Success response missing token_type is rejected."""
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": "tok",
                    "issued_token_type": ACCESS_TOKEN,
                },
            )
        )
        response = exchange_token(
            TokenExchangeRequest(
                address=TOKEN_URL,
                client_id="service-a",
                subject_token="tok",
                subject_token_type=ACCESS_TOKEN,
                client_secret="secret",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "token_type" in response.error

    @respx.mock
    def test_empty_success_response_returns_error(self):
        """BH M1: Empty dict success response is rejected."""
        respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json={}))
        response = exchange_token(
            TokenExchangeRequest(
                address=TOKEN_URL,
                client_id="service-a",
                subject_token="tok",
                subject_token_type=ACCESS_TOKEN,
                client_secret="secret",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "access_token" in response.error
        assert "token_type" in response.error

    def test_validation_error_label(self):
        """BH M2: ValueError gives 'Validation error' label, not 'Unexpected'."""
        response = exchange_token(
            TokenExchangeRequest(
                address=TOKEN_URL,
                client_id="service-a",
                subject_token="",
                subject_token_type=ACCESS_TOKEN,
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "Validation error" in response.error
        assert "Unexpected" not in response.error

    @respx.mock
    def test_error_response_parses_rfc6749(self):
        """BH M3: Error response extracts RFC 6749 §5.2 fields."""
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                400,
                json={
                    "error": "invalid_grant",
                    "error_description": "Subject token expired",
                },
            )
        )
        response = exchange_token(
            TokenExchangeRequest(
                address=TOKEN_URL,
                client_id="service-a",
                subject_token="tok",
                subject_token_type=ACCESS_TOKEN,
                client_secret="secret",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "invalid_grant" in response.error
        assert "Subject token expired" in response.error

    def test_actor_token_type_without_actor_token_returns_error(self):
        """WARN #4/S5: actor_token_type without actor_token is rejected."""
        response = exchange_token(
            TokenExchangeRequest(
                address=TOKEN_URL,
                client_id="service-a",
                subject_token="user-token",
                subject_token_type=ACCESS_TOKEN,
                actor_token_type=JWT,
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "actor_token_type has no meaning without actor_token" in response.error

    def test_empty_client_id_returns_error(self):
        """S4: Empty client_id returns error response."""
        response = exchange_token(
            TokenExchangeRequest(
                address=TOKEN_URL,
                client_id="",
                subject_token="tok",
                subject_token_type=ACCESS_TOKEN,
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "client_id must not be empty" in response.error

    @respx.mock
    def test_empty_optional_fields_not_sent(self):
        """S6: Empty optional string fields are not included in request."""
        route = respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=TOKEN_EXCHANGE_RESPONSE)
        )
        exchange_token(
            TokenExchangeRequest(
                address=TOKEN_URL,
                client_id="service-a",
                subject_token="tok",
                subject_token_type=ACCESS_TOKEN,
                resource="",
                audience="",
                scope="",
                requested_token_type="",
                client_secret="secret",
            )
        )
        body = route.calls[0].request.content.decode()
        assert "resource=" not in body
        assert "audience=" not in body
        assert "scope=" not in body
        assert "requested_token_type=" not in body

    @respx.mock
    def test_non_string_issued_token_type_ignored(self):
        """S8: Non-string issued_token_type is set to None."""
        resp_data = {
            **TOKEN_EXCHANGE_RESPONSE,
            "issued_token_type": 123,
        }
        respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json=resp_data))
        response = exchange_token(
            TokenExchangeRequest(
                address=TOKEN_URL,
                client_id="service-a",
                subject_token="tok",
                subject_token_type=ACCESS_TOKEN,
                client_secret="secret",
            )
        )
        assert response.is_successful is True
        assert response.issued_token_type is None


@pytest.mark.unit
class TestTokenExchangeModels:
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

    def test_response_success_fields(self):
        resp = TokenExchangeResponse(
            is_successful=True,
            token={"access_token": "new-tok", "token_type": "Bearer"},
            issued_token_type=token_type.ACCESS_TOKEN,
        )
        assert resp.token is not None
        assert resp.token["access_token"] == "new-tok"
        assert resp.issued_token_type == token_type.ACCESS_TOKEN

    def test_token_type_constants(self):
        assert token_type.ACCESS_TOKEN.startswith("urn:ietf:params:oauth:")
        assert token_type.REFRESH_TOKEN.startswith("urn:ietf:params:oauth:")
        assert token_type.ID_TOKEN.startswith("urn:ietf:params:oauth:")
        assert token_type.SAML1.startswith("urn:ietf:params:oauth:")
        assert token_type.SAML2.startswith("urn:ietf:params:oauth:")
        assert token_type.JWT.startswith("urn:ietf:params:oauth:")


@pytest.mark.unit
class TestPrepareTokenExchangeData:
    def test_impersonation(self):
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

    def test_delegation(self):
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

    def test_all_optional_fields(self):
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
