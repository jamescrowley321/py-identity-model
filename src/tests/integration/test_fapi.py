"""Integration tests for FAPI 2.0 Security Profile compliance."""

import pytest

from py_identity_model import (
    FAPI2_ALLOWED_SIGNING_ALGORITHMS,
    FAPIValidationResult,
    validate_fapi_authorization_request,
    validate_fapi_client_config,
    validate_fapi_discovery,
)
from py_identity_model.core.models import DiscoveryDocumentResponse


@pytest.mark.integration
class TestFAPIIntegration:
    def test_full_compliant_flow_validation(self):
        """Validate a complete FAPI 2.0 compliant flow."""
        auth_result = validate_fapi_authorization_request(
            response_type="code",
            code_challenge="fapi_challenge_value",
            code_challenge_method="S256",
            redirect_uri="https://bank.example.com/callback",
            use_par=True,
            algorithm="PS256",
        )
        assert auth_result.is_compliant is True

        client_result = validate_fapi_client_config(
            has_client_authentication=True,
            use_dpop=True,
        )
        assert client_result.is_compliant is True

    def test_validation_result_dataclass(self):
        result = FAPIValidationResult(
            is_compliant=False,
            violations=["test violation"],
        )
        assert result.is_compliant is False
        assert result.violations == ["test violation"]

    def test_discovery_with_tls_client_auth(self):
        disco = DiscoveryDocumentResponse(
            is_successful=True,
            issuer="https://fapi.example.com",
            grant_types_supported=["authorization_code"],
            token_endpoint_auth_methods_supported=["tls_client_auth"],
            id_token_signing_alg_values_supported=["PS256"],
        )
        result = validate_fapi_discovery(disco)
        assert result.is_compliant is True

    def test_discovery_with_self_signed_tls(self):
        disco = DiscoveryDocumentResponse(
            is_successful=True,
            issuer="https://fapi.example.com",
            grant_types_supported=["authorization_code"],
            token_endpoint_auth_methods_supported=[
                "self_signed_tls_client_auth"
            ],
            id_token_signing_alg_values_supported=["ES256"],
        )
        result = validate_fapi_discovery(disco)
        assert result.is_compliant is True

    def test_top_level_import(self):
        from py_identity_model import (
            FAPI2_REQUIRED_PKCE_METHOD,
            FAPI2_REQUIRED_RESPONSE_TYPE,
            FAPIValidationResult,
            validate_fapi_authorization_request,
            validate_fapi_client_config,
            validate_fapi_discovery,
        )

        assert callable(validate_fapi_authorization_request)
        assert callable(validate_fapi_client_config)
        assert callable(validate_fapi_discovery)
        assert FAPIValidationResult is not None
        assert FAPI2_ALLOWED_SIGNING_ALGORITHMS is not None
        assert FAPI2_REQUIRED_PKCE_METHOD is not None
        assert FAPI2_REQUIRED_RESPONSE_TYPE is not None

    def test_aio_import(self):
        from py_identity_model.aio import (
            FAPI2_ALLOWED_SIGNING_ALGORITHMS,
            FAPIValidationResult,
            validate_fapi_authorization_request,
            validate_fapi_client_config,
            validate_fapi_discovery,
        )

        assert callable(validate_fapi_authorization_request)
        assert callable(validate_fapi_client_config)
        assert callable(validate_fapi_discovery)
        assert FAPIValidationResult is not None
        assert FAPI2_ALLOWED_SIGNING_ALGORITHMS is not None
