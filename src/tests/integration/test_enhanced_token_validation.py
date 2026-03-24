"""Integration tests for enhanced token validation features."""

import pytest

from py_identity_model import TokenValidationConfig, validate_token


@pytest.mark.integration
class TestEnhancedTokenValidation:
    """Test enhanced validation features against real tokens."""

    def test_leeway_with_real_token(
        self, client_credentials_token, test_config
    ):
        """Validate a real token with leeway configured."""
        token = client_credentials_token.token["access_token"]
        config = TokenValidationConfig(
            perform_disco=True,
            audience=test_config.get("TEST_AUDIENCE") or None,
            leeway=60,
            options={"verify_aud": False, "require_aud": False},
        )

        decoded = validate_token(
            token,
            config,
            disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
        )
        assert "iss" in decoded

    def test_issuer_validation_with_real_token(
        self, client_credentials_token, test_config, issuer
    ):
        """Validate issuer against real discovery document issuer."""
        token = client_credentials_token.token["access_token"]
        config = TokenValidationConfig(
            perform_disco=True,
            issuer=issuer,
            options={"verify_aud": False, "require_aud": False},
        )

        decoded = validate_token(
            token,
            config,
            disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
        )
        assert decoded["iss"] == issuer

    def test_multi_issuer_with_real_token(
        self, client_credentials_token, test_config, issuer
    ):
        """Validate token against a list of accepted issuers."""
        token = client_credentials_token.token["access_token"]
        config = TokenValidationConfig(
            perform_disco=True,
            issuer=[issuer, "https://other-idp.example.com"],
            options={"verify_aud": False, "require_aud": False},
        )

        decoded = validate_token(
            token,
            config,
            disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
        )
        assert decoded["iss"] == issuer

    def test_wrong_multi_issuer_list_still_matches_discovery(
        self, client_credentials_token, test_config, issuer
    ):
        """Config issuer list is overridden by discovery document issuer."""
        token = client_credentials_token.token["access_token"]
        # When perform_disco=True, the discovery document's issuer takes
        # precedence over the config issuer (this is correct behavior).
        config = TokenValidationConfig(
            perform_disco=True,
            issuer=["https://other.example.com"],
            options={"verify_aud": False, "require_aud": False},
        )

        # Succeeds because disco document issuer overrides config issuer
        decoded = validate_token(
            token,
            config,
            disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
        )
        assert decoded["iss"] == issuer
