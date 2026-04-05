"""Unit tests for BaseResponse guarded field access, repr, and equality."""

import pytest

from py_identity_model import (
    BaseResponse,
    DiscoveryDocumentResponse,
    JwksResponse,
    UserInfoResponse,
)
from py_identity_model.core.models import ClientCredentialsTokenResponse
from py_identity_model.exceptions import (
    FailedResponseAccessError,
    SuccessfulResponseAccessError,
)


@pytest.mark.unit
class TestBaseResponse:
    """Tests for BaseResponse base class."""

    def test_successful_response_guards_error(self):
        resp = BaseResponse(is_successful=True)
        with pytest.raises(SuccessfulResponseAccessError):
            _ = resp.error

    def test_failed_response_allows_error(self):
        resp = BaseResponse(is_successful=False, error="test")
        assert resp.error == "test"

    def test_response_guard_through_inheritance(self):
        resp = JwksResponse(is_successful=False, error="network error")
        with pytest.raises(FailedResponseAccessError, match="keys"):
            _ = resp.keys

    # ------------------------------------------------------------------
    # repr / eq safety (review-fix: Blind Hunter MUST FIX)
    # ------------------------------------------------------------------

    def test_repr_successful_response_does_not_crash(self):
        """repr() must not trigger field-access guards on successful responses."""
        resp = JwksResponse(is_successful=True, keys=[])
        text = repr(resp)
        assert "JwksResponse" in text
        assert "is_successful=True" in text

    def test_repr_failed_response_does_not_crash(self):
        """repr() must not trigger field-access guards on failed responses."""
        resp = JwksResponse(is_successful=False, error="network error")
        text = repr(resp)
        assert "JwksResponse" in text
        assert "network error" in text

    @pytest.mark.parametrize(
        ("cls", "kwargs"),
        [
            (BaseResponse, {"is_successful": True}),
            (DiscoveryDocumentResponse, {"is_successful": True}),
            (
                ClientCredentialsTokenResponse,
                {"is_successful": False, "error": "e"},
            ),
            (
                UserInfoResponse,
                {"is_successful": True, "claims": {"sub": "u"}},
            ),
        ],
        ids=["base", "discovery", "token", "userinfo"],
    )
    def test_repr_all_response_types(self, cls, kwargs):
        """repr() must not crash on any BaseResponse subclass."""
        resp = cls(**kwargs)
        text = repr(resp)
        assert cls.__name__ in text

    def test_eq_successful_responses(self):
        """Equality must not trigger field-access guards."""
        r1 = JwksResponse(is_successful=True, keys=[])
        r2 = JwksResponse(is_successful=True, keys=[])
        assert r1 == r2

    def test_eq_failed_responses(self):
        """Equality must not trigger field-access guards on failed responses."""
        r1 = JwksResponse(is_successful=False, error="err")
        r2 = JwksResponse(is_successful=False, error="err")
        assert r1 == r2

    def test_eq_different_types_returns_not_implemented(self):
        """Equality between different response types returns NotImplemented."""
        r1 = JwksResponse(is_successful=True, keys=[])
        r2 = BaseResponse(is_successful=True)
        assert r1 != r2

    def test_repr_in_fstring(self):
        """f-string interpolation must not crash (common logging pattern)."""
        resp = JwksResponse(is_successful=False, error="timeout")
        text = f"Validation failed: {resp}"
        assert "timeout" in text
