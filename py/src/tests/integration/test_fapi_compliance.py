"""Integration tests for FAPI 2.0 Security Profile compliance.

These tests validate a live provider's discovery document against
FAPI 2.0 requirements and test the validation helpers with real
provider metadata.
"""

import pytest

from py_identity_model import (
    validate_fapi_authorization_request,
    validate_fapi_client_config,
    validate_fapi_discovery,
)


@pytest.mark.integration
class TestFAPIDiscoveryCompliance:
    """Validate a live provider's discovery document against FAPI 2.0."""

    def test_validate_live_discovery(self, discovery_document):
        """Run FAPI 2.0 discovery validation against the live provider.

        Most test providers won't be FAPI-compliant.  This test verifies
        the validation runs without error and produces a meaningful result.
        """
        result = validate_fapi_discovery(discovery_document)

        # Result should always be well-formed
        assert isinstance(result.violations, list)
        assert isinstance(result.is_compliant, bool)
        assert result.is_compliant == (len(result.violations) == 0)

    def test_fapi_violations_are_descriptive(self, discovery_document):
        """Each violation string describes what's wrong."""
        result = validate_fapi_discovery(discovery_document)

        for violation in result.violations:
            assert isinstance(violation, str)
            assert len(violation) > 0

    def test_pkce_requirement_detection(self, raw_discovery):
        """Detect whether the provider supports S256 PKCE (required by FAPI)."""
        methods = raw_discovery.get("code_challenge_methods_supported", [])

        # Build a FAPI auth request to check if S256 is available
        result = validate_fapi_authorization_request(
            response_type="code",
            code_challenge="test-challenge" if "S256" in methods else None,
            code_challenge_method="S256" if "S256" in methods else None,
            redirect_uri="https://secure.example.com/callback",
            use_par=True,
            algorithm="PS256",
        )

        if "S256" in methods:
            # With proper PKCE, the only potential violation is PAR
            pkce_violations = [
                v for v in result.violations if "PKCE" in v or "S256" in v
            ]
            assert len(pkce_violations) == 0
        else:
            # Without S256, FAPI should flag a violation
            assert result.is_compliant is False


@pytest.mark.integration
class TestFAPIClientConfigValidation:
    """Test FAPI client configuration validation with real provider context."""

    def test_private_key_jwt_with_dpop(self):
        """Strongest FAPI client config: private_key_jwt + DPoP."""
        result = validate_fapi_client_config(
            auth_method="private_key_jwt",
            use_dpop=True,
        )
        assert result.is_compliant is True

    def test_tls_client_auth_with_mtls(self):
        """mTLS-based FAPI client config."""
        result = validate_fapi_client_config(
            auth_method="tls_client_auth",
            use_mtls=True,
        )
        assert result.is_compliant is True

    def test_client_secret_basic_rejected(self):
        """FAPI rejects client_secret_basic auth method."""
        result = validate_fapi_client_config(
            auth_method="client_secret_basic",
        )
        assert result.is_compliant is False
        assert any("auth method" in v.lower() for v in result.violations)

    def test_no_sender_constraining_rejected(self):
        """FAPI requires sender-constraining (DPoP or mTLS)."""
        result = validate_fapi_client_config(
            auth_method="private_key_jwt",
            use_dpop=False,
            use_mtls=False,
        )
        assert result.is_compliant is False
        assert any(
            "sender" in v.lower() or "constrain" in v.lower() for v in result.violations
        )


@pytest.mark.integration
class TestFAPIAuthRequestValidation:
    """Test FAPI authorization request validation patterns."""

    def test_fully_compliant_request(self):
        """A request meeting all FAPI 2.0 requirements passes."""
        result = validate_fapi_authorization_request(
            response_type="code",
            code_challenge="valid-challenge",
            code_challenge_method="S256",
            redirect_uri="https://bank.example.com/callback",
            use_par=True,
            algorithm="PS256",
        )
        assert result.is_compliant is True
        assert len(result.violations) == 0

    def test_implicit_flow_rejected(self):
        """FAPI 2.0 requires authorization code flow."""
        result = validate_fapi_authorization_request(
            response_type="token",
            code_challenge=None,
            code_challenge_method=None,
            redirect_uri="https://bank.example.com/callback",
            use_par=True,
            algorithm="PS256",
        )
        assert result.is_compliant is False
        assert any(
            "code" in v.lower() or "response_type" in v.lower()
            for v in result.violations
        )

    def test_http_redirect_uri_rejected(self):
        """FAPI 2.0 requires HTTPS redirect URIs."""
        result = validate_fapi_authorization_request(
            response_type="code",
            code_challenge="challenge",
            code_challenge_method="S256",
            redirect_uri="http://insecure.example.com/callback",
            use_par=True,
            algorithm="PS256",
        )
        assert result.is_compliant is False

    def test_missing_par_rejected(self):
        """FAPI 2.0 requires Pushed Authorization Requests."""
        result = validate_fapi_authorization_request(
            response_type="code",
            code_challenge="challenge",
            code_challenge_method="S256",
            redirect_uri="https://bank.example.com/callback",
            use_par=False,
            algorithm="PS256",
        )
        assert result.is_compliant is False
        assert any("PAR" in v or "pushed" in v.lower() for v in result.violations)
