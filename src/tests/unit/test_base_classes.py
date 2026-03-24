"""Unit tests for BaseRequest and BaseResponse base classes."""

import pytest

from py_identity_model import (
    BaseRequest,
    BaseResponse,
    ClientCredentialsTokenRequest,
    DiscoveryDocumentRequest,
    DiscoveryDocumentResponse,
    JwksRequest,
    JwksResponse,
    UserInfoRequest,
    UserInfoResponse,
)
from py_identity_model.core.authorize_response import AuthorizeCallbackResponse
from py_identity_model.core.models import ClientCredentialsTokenResponse
from py_identity_model.exceptions import (
    FailedResponseAccessError,
    SuccessfulResponseAccessError,
)


@pytest.mark.unit
class TestBaseRequest:
    """Tests for BaseRequest base class."""

    def test_base_request_has_address(self):
        req = BaseRequest(address="https://example.com")
        assert req.address == "https://example.com"

    @pytest.mark.parametrize(
        "cls",
        [
            DiscoveryDocumentRequest,
            JwksRequest,
            ClientCredentialsTokenRequest,
            UserInfoRequest,
        ],
        ids=["discovery", "jwks", "token", "userinfo"],
    )
    def test_all_requests_inherit_from_base(self, cls):
        assert issubclass(cls, BaseRequest)

    def test_discovery_request_isinstance(self):
        req = DiscoveryDocumentRequest(address="https://example.com")
        assert isinstance(req, BaseRequest)

    def test_token_request_isinstance(self):
        req = ClientCredentialsTokenRequest(
            address="https://example.com/token",
            client_id="id",
            client_secret="secret",
            scope="api",
        )
        assert isinstance(req, BaseRequest)
        assert req.address == "https://example.com/token"

    def test_userinfo_request_isinstance(self):
        req = UserInfoRequest(
            address="https://example.com/userinfo", token="tok"
        )
        assert isinstance(req, BaseRequest)
        assert req.token == "tok"


@pytest.mark.unit
class TestBaseResponse:
    """Tests for BaseResponse base class."""

    def test_base_response_fields(self):
        resp = BaseResponse(is_successful=True)
        assert resp.is_successful is True

    def test_base_response_error(self):
        resp = BaseResponse(is_successful=False, error="fail")
        assert resp.error == "fail"

    @pytest.mark.parametrize(
        "cls",
        [
            DiscoveryDocumentResponse,
            JwksResponse,
            ClientCredentialsTokenResponse,
            UserInfoResponse,
        ],
        ids=["discovery", "jwks", "token", "userinfo"],
    )
    def test_all_responses_inherit_from_base(self, cls):
        assert issubclass(cls, BaseResponse)

    def test_authorize_callback_does_not_inherit(self):
        """AuthorizeCallbackResponse uses _GuardedResponseMixin directly."""
        assert not issubclass(AuthorizeCallbackResponse, BaseResponse)

    def test_successful_response_guards_error(self):
        resp = BaseResponse(is_successful=True)
        with pytest.raises(SuccessfulResponseAccessError):
            _ = resp.error

    def test_failed_response_allows_error(self):
        resp = BaseResponse(is_successful=False, error="test")
        assert resp.error == "test"

    def test_jwks_response_isinstance(self):
        resp = JwksResponse(is_successful=True, keys=[])
        assert isinstance(resp, BaseResponse)

    def test_response_guard_through_inheritance(self):
        resp = JwksResponse(is_successful=False, error="network error")
        with pytest.raises(FailedResponseAccessError, match="keys"):
            _ = resp.keys
