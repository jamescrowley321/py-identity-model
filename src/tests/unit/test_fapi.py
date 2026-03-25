"""Unit tests for FAPI 2.0 Security Profile compliance validation."""

import pytest

from py_identity_model.core.fapi import (
    FAPI2_ALLOWED_SIGNING_ALGORITHMS,
    FAPI2_REQUIRED_PKCE_METHOD,
    FAPI2_REQUIRED_RESPONSE_TYPE,
    validate_fapi_authorization_request,
    validate_fapi_client_config,
    validate_fapi_discovery,
)
from py_identity_model.core.models import DiscoveryDocumentResponse


@pytest.mark.unit
class TestValidateFAPIAuthorizationRequest:
    def test_compliant_request(self):
        result = validate_fapi_authorization_request(
            response_type="code",
            code_challenge="challenge_value",
            code_challenge_method="S256",
            redirect_uri="https://app.example.com/callback",
            use_par=True,
            algorithm="ES256",
        )
        assert result.is_compliant is True
        assert result.violations == []

    def test_wrong_response_type(self):
        result = validate_fapi_authorization_request(
            response_type="token",
            code_challenge="challenge",
            code_challenge_method="S256",
            redirect_uri="https://app.example.com/cb",
            use_par=True,
        )
        assert result.is_compliant is False
        assert any("response_type" in v for v in result.violations)

    def test_missing_code_challenge(self):
        result = validate_fapi_authorization_request(
            response_type="code",
            code_challenge=None,
            code_challenge_method="S256",
            redirect_uri="https://app.example.com/cb",
            use_par=True,
        )
        assert result.is_compliant is False
        assert any("code_challenge" in v for v in result.violations)

    def test_wrong_pkce_method(self):
        result = validate_fapi_authorization_request(
            response_type="code",
            code_challenge="challenge",
            code_challenge_method="plain",
            redirect_uri="https://app.example.com/cb",
            use_par=True,
        )
        assert result.is_compliant is False
        assert any("S256" in v for v in result.violations)

    def test_par_not_used(self):
        result = validate_fapi_authorization_request(
            response_type="code",
            code_challenge="challenge",
            code_challenge_method="S256",
            redirect_uri="https://app.example.com/cb",
            use_par=False,
        )
        assert result.is_compliant is False
        assert any("PAR" in v for v in result.violations)

    def test_http_redirect_uri(self):
        result = validate_fapi_authorization_request(
            response_type="code",
            code_challenge="challenge",
            code_challenge_method="S256",
            redirect_uri="http://app.example.com/cb",
            use_par=True,
        )
        assert result.is_compliant is False
        assert any("HTTPS" in v for v in result.violations)

    def test_disallowed_algorithm(self):
        result = validate_fapi_authorization_request(
            response_type="code",
            code_challenge="challenge",
            code_challenge_method="S256",
            redirect_uri="https://app.example.com/cb",
            use_par=True,
            algorithm="RS256",
        )
        assert result.is_compliant is False
        assert any("RS256" in v for v in result.violations)

    def test_algorithm_none_is_ok(self):
        result = validate_fapi_authorization_request(
            response_type="code",
            code_challenge="challenge",
            code_challenge_method="S256",
            redirect_uri="https://app.example.com/cb",
            use_par=True,
            algorithm=None,
        )
        assert result.is_compliant is True

    def test_multiple_violations(self):
        result = validate_fapi_authorization_request(
            response_type="token",
            code_challenge=None,
            code_challenge_method="plain",
            redirect_uri="http://app.example.com/cb",
            use_par=False,
            algorithm="RS256",
        )
        assert result.is_compliant is False
        assert len(result.violations) == 6


@pytest.mark.unit
class TestValidateFAPIClientConfig:
    def test_compliant_dpop(self):
        result = validate_fapi_client_config(
            has_client_authentication=True,
            use_dpop=True,
        )
        assert result.is_compliant is True

    def test_compliant_mtls(self):
        result = validate_fapi_client_config(
            has_client_authentication=True,
            use_mtls=True,
        )
        assert result.is_compliant is True

    def test_no_client_auth(self):
        result = validate_fapi_client_config(
            has_client_authentication=False,
            use_dpop=True,
        )
        assert result.is_compliant is False
        assert any("Client authentication" in v for v in result.violations)

    def test_no_sender_constraint(self):
        result = validate_fapi_client_config(
            has_client_authentication=True,
            use_dpop=False,
            use_mtls=False,
        )
        assert result.is_compliant is False
        assert any("Sender-constrained" in v for v in result.violations)

    def test_both_dpop_and_mtls(self):
        result = validate_fapi_client_config(
            has_client_authentication=True,
            use_dpop=True,
            use_mtls=True,
        )
        assert result.is_compliant is True


@pytest.mark.unit
class TestValidateFAPIDiscovery:
    def test_compliant_discovery(self):
        disco = DiscoveryDocumentResponse(
            is_successful=True,
            issuer="https://auth.example.com",
            grant_types_supported=["authorization_code"],
            token_endpoint_auth_methods_supported=["private_key_jwt"],
            id_token_signing_alg_values_supported=["ES256", "PS256"],
        )
        result = validate_fapi_discovery(disco)
        assert result.is_compliant is True

    def test_missing_auth_code_grant(self):
        disco = DiscoveryDocumentResponse(
            is_successful=True,
            issuer="https://auth.example.com",
            grant_types_supported=["client_credentials"],
            token_endpoint_auth_methods_supported=["private_key_jwt"],
            id_token_signing_alg_values_supported=["ES256"],
        )
        result = validate_fapi_discovery(disco)
        assert result.is_compliant is False
        assert any("authorization_code" in v for v in result.violations)

    def test_weak_auth_methods(self):
        disco = DiscoveryDocumentResponse(
            is_successful=True,
            issuer="https://auth.example.com",
            grant_types_supported=["authorization_code"],
            token_endpoint_auth_methods_supported=["client_secret_basic"],
            id_token_signing_alg_values_supported=["ES256"],
        )
        result = validate_fapi_discovery(disco)
        assert result.is_compliant is False
        assert any("client auth" in v for v in result.violations)

    def test_weak_algorithms(self):
        disco = DiscoveryDocumentResponse(
            is_successful=True,
            issuer="https://auth.example.com",
            grant_types_supported=["authorization_code"],
            token_endpoint_auth_methods_supported=["private_key_jwt"],
            id_token_signing_alg_values_supported=["RS256"],
        )
        result = validate_fapi_discovery(disco)
        assert result.is_compliant is False
        assert any("signing algorithms" in v for v in result.violations)

    def test_none_fields_pass(self):
        disco = DiscoveryDocumentResponse(
            is_successful=True,
            issuer="https://auth.example.com",
        )
        result = validate_fapi_discovery(disco)
        assert result.is_compliant is True
        assert result.violations == []


@pytest.mark.unit
class TestFAPIConstants:
    def test_allowed_algorithms(self):
        assert "ES256" in FAPI2_ALLOWED_SIGNING_ALGORITHMS
        assert "PS256" in FAPI2_ALLOWED_SIGNING_ALGORITHMS
        assert "RS256" not in FAPI2_ALLOWED_SIGNING_ALGORITHMS

    def test_required_pkce_method(self):
        assert FAPI2_REQUIRED_PKCE_METHOD == "S256"

    def test_required_response_type(self):
        assert FAPI2_REQUIRED_RESPONSE_TYPE == "code"
