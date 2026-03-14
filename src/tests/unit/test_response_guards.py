"""Tests for response model guarded field access."""

import pytest

from py_identity_model.core.models import (
    ClientCredentialsTokenResponse,
    DiscoveryDocumentResponse,
    JwksResponse,
    UserInfoResponse,
)
from py_identity_model.exceptions import (
    FailedResponseAccessError,
    SuccessfulResponseAccessError,
)


class TestJwksResponseGuards:
    def test_successful_response_allows_keys_access(self):
        response = JwksResponse(is_successful=True, keys=[])
        assert response.keys == []

    def test_failed_response_blocks_keys_access(self):
        response = JwksResponse(
            is_successful=False,
            error="Network error during JWKS request",
        )
        with pytest.raises(FailedResponseAccessError, match="keys"):
            _ = response.keys

    def test_failed_response_error_message_includes_original_error(self):
        response = JwksResponse(
            is_successful=False,
            error="Connection refused",
        )
        with pytest.raises(
            FailedResponseAccessError, match="Connection refused"
        ):
            _ = response.keys

    def test_failed_response_allows_is_successful_access(self):
        response = JwksResponse(is_successful=False, error="some error")
        assert response.is_successful is False

    def test_failed_response_allows_error_access(self):
        response = JwksResponse(is_successful=False, error="some error")
        assert response.error == "some error"

    def test_successful_response_blocks_error_access(self):
        response = JwksResponse(is_successful=True, keys=[])
        with pytest.raises(SuccessfulResponseAccessError, match="error"):
            _ = response.error

    def test_successful_response_allows_is_successful_access(self):
        response = JwksResponse(is_successful=True, keys=[])
        assert response.is_successful is True


class TestClientCredentialsTokenResponseGuards:
    def test_successful_response_allows_token_access(self):
        response = ClientCredentialsTokenResponse(
            is_successful=True, token={"access_token": "abc"}
        )
        assert response.token == {"access_token": "abc"}

    def test_failed_response_blocks_token_access(self):
        response = ClientCredentialsTokenResponse(
            is_successful=False,
            error="Invalid credentials",
        )
        with pytest.raises(FailedResponseAccessError, match="token"):
            _ = response.token

    def test_successful_response_blocks_error_access(self):
        response = ClientCredentialsTokenResponse(
            is_successful=True, token={"access_token": "abc"}
        )
        with pytest.raises(SuccessfulResponseAccessError, match="error"):
            _ = response.error


class TestUserInfoResponseGuards:
    def test_successful_response_allows_claims_access(self):
        response = UserInfoResponse(is_successful=True, claims={"sub": "123"})
        assert response.claims == {"sub": "123"}

    def test_failed_response_blocks_claims_access(self):
        response = UserInfoResponse(is_successful=False, error="Unauthorized")
        with pytest.raises(FailedResponseAccessError, match="claims"):
            _ = response.claims

    def test_failed_response_blocks_raw_access(self):
        response = UserInfoResponse(is_successful=False, error="Unauthorized")
        with pytest.raises(FailedResponseAccessError, match="raw"):
            _ = response.raw

    def test_successful_response_blocks_error_access(self):
        response = UserInfoResponse(is_successful=True, claims={"sub": "123"})
        with pytest.raises(SuccessfulResponseAccessError, match="error"):
            _ = response.error


class TestDiscoveryDocumentResponseGuards:
    def test_successful_response_allows_field_access(self):
        response = DiscoveryDocumentResponse(
            is_successful=True,
            issuer="https://example.com",
            jwks_uri="https://example.com/jwks",
        )
        assert response.issuer == "https://example.com"
        assert response.jwks_uri == "https://example.com/jwks"

    def test_failed_response_blocks_issuer_access(self):
        response = DiscoveryDocumentResponse(
            is_successful=False, error="Not found"
        )
        with pytest.raises(FailedResponseAccessError, match="issuer"):
            _ = response.issuer

    def test_failed_response_blocks_jwks_uri_access(self):
        response = DiscoveryDocumentResponse(
            is_successful=False, error="Not found"
        )
        with pytest.raises(FailedResponseAccessError, match="jwks_uri"):
            _ = response.jwks_uri

    def test_failed_response_blocks_token_endpoint_access(self):
        response = DiscoveryDocumentResponse(
            is_successful=False, error="Not found"
        )
        with pytest.raises(FailedResponseAccessError, match="token_endpoint"):
            _ = response.token_endpoint

    def test_successful_response_blocks_error_access(self):
        response = DiscoveryDocumentResponse(
            is_successful=True,
            issuer="https://example.com",
            jwks_uri="https://example.com/jwks",
        )
        with pytest.raises(SuccessfulResponseAccessError, match="error"):
            _ = response.error


class TestFailedResponseAccessError:
    def test_error_includes_field_name(self):
        err = FailedResponseAccessError("keys", "some error")
        assert "keys" in str(err)

    def test_error_includes_original_error(self):
        err = FailedResponseAccessError("keys", "Connection refused")
        assert "Connection refused" in str(err)

    def test_error_without_original_error(self):
        err = FailedResponseAccessError("keys")
        assert "keys" in str(err)
        assert "Check 'is_successful'" in str(err)

    def test_error_stores_field_name(self):
        err = FailedResponseAccessError("keys", "some error")
        assert err.field_name == "keys"


class TestSuccessfulResponseAccessError:
    def test_error_includes_field_name(self):
        err = SuccessfulResponseAccessError("error")
        assert "error" in str(err)

    def test_error_includes_check_guidance(self):
        err = SuccessfulResponseAccessError("error")
        assert "Check 'is_successful'" in str(err)

    def test_error_mentions_successful_response(self):
        err = SuccessfulResponseAccessError("error")
        assert "successful response" in str(err)

    def test_error_stores_field_name(self):
        err = SuccessfulResponseAccessError("error")
        assert err.field_name == "error"

    def test_default_field_name(self):
        err = SuccessfulResponseAccessError()
        assert err.field_name == "error"
