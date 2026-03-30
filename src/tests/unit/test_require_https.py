"""
Unit tests for the require_https parameter threading.

Covers require_https support across:
- validators.validate_issuer
- response_processors.validate_and_parse_discovery_response
- models.DiscoveryDocumentRequest
- models.TokenValidationConfig
- sync/async discovery flow
- "none" response type validation
"""

import httpx
import pytest
import respx

from py_identity_model.core.models import (
    DiscoveryDocumentRequest,
    TokenValidationConfig,
)
from py_identity_model.core.response_processors import (
    validate_and_parse_discovery_response,
)
from py_identity_model.core.validators import (
    validate_issuer,
    validate_parameter_values,
)
from py_identity_model.exceptions import (
    ConfigurationException,
    DiscoveryException,
)


# ============================================================================
# Helper: minimal valid discovery JSON
# ============================================================================


def _valid_disco_json(issuer="https://example.com"):
    """Return a minimal valid discovery document dict."""
    return {
        "issuer": issuer,
        "jwks_uri": "https://example.com/jwks",
        "authorization_endpoint": "https://example.com/auth",
        "token_endpoint": "https://example.com/token",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }


def _http_disco_json():
    """Return a discovery document with HTTP issuer and endpoints."""
    return {
        "issuer": "http://localhost:8080",
        "jwks_uri": "http://localhost:8080/jwks",
        "authorization_endpoint": "http://localhost:8080/auth",
        "token_endpoint": "http://localhost:8080/token",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }


# ============================================================================
# 1. validate_issuer with require_https
# ============================================================================


class TestValidateIssuerRequireHttps:
    """Tests for validate_issuer with the require_https parameter."""

    def test_http_issuer_with_require_https_false_passes(self):
        """HTTP issuer should pass when require_https=False."""
        validate_issuer("http://localhost:8080", require_https=False)

    def test_http_issuer_with_require_https_true_fails(self):
        """HTTP issuer should fail when require_https=True (default)."""
        with pytest.raises(
            ConfigurationException, match="must use HTTPS scheme"
        ):
            validate_issuer("http://localhost:8080", require_https=True)

    def test_http_issuer_with_default_require_https_fails(self):
        """HTTP issuer should fail with default require_https (True)."""
        with pytest.raises(
            ConfigurationException, match="must use HTTPS scheme"
        ):
            validate_issuer("http://localhost:8080")

    def test_https_issuer_with_require_https_false_passes(self):
        """HTTPS issuer should pass when require_https=False."""
        validate_issuer("https://example.com", require_https=False)

    def test_https_issuer_with_require_https_true_passes(self):
        """HTTPS issuer should pass when require_https=True."""
        validate_issuer("https://example.com", require_https=True)

    def test_non_http_scheme_fails_regardless_of_require_https(self):
        """Non-HTTP/HTTPS schemes should fail even when require_https=False."""
        for scheme in ["ftp://example.com", "ws://example.com", "file:///tmp"]:
            with pytest.raises(
                ConfigurationException,
                match="must use HTTP or HTTPS scheme",
            ):
                validate_issuer(scheme, require_https=False)

    def test_non_http_scheme_fails_with_require_https_true(self):
        """Non-HTTP/HTTPS schemes should fail when require_https=True."""
        with pytest.raises(
            ConfigurationException,
            match="must use HTTPS scheme",
        ):
            validate_issuer("ftp://example.com", require_https=True)

    def test_require_https_none_treated_as_falsy(self):
        """require_https=None should be treated as falsy, allowing HTTP."""
        # None is falsy in Python, so it goes to the elif branch
        validate_issuer("http://localhost:8080", require_https=None)  # type: ignore[arg-type]

    def test_require_https_none_rejects_non_http_scheme(self):
        """require_https=None (falsy) should still reject non-HTTP schemes."""
        with pytest.raises(
            ConfigurationException,
            match="must use HTTP or HTTPS scheme",
        ):
            validate_issuer("ftp://example.com", require_https=None)  # type: ignore[arg-type]


# ============================================================================
# 2. validate_and_parse_discovery_response with require_https
# ============================================================================


class TestValidateAndParseDiscoveryResponseRequireHttps:
    """Tests for validate_and_parse_discovery_response with require_https."""

    def test_http_issuer_passes_with_require_https_false(self):
        """HTTP issuer in discovery doc should pass when require_https=False."""
        response = httpx.Response(
            200,
            json=_http_disco_json(),
            headers={"Content-Type": "application/json"},
        )
        result = validate_and_parse_discovery_response(
            response, require_https=False
        )
        assert result["issuer"] == "http://localhost:8080"

    def test_http_issuer_fails_with_require_https_true(self):
        """HTTP issuer in discovery doc should fail when require_https=True."""
        response = httpx.Response(
            200,
            json=_http_disco_json(),
            headers={"Content-Type": "application/json"},
        )
        with pytest.raises(
            ConfigurationException, match="must use HTTPS scheme"
        ):
            validate_and_parse_discovery_response(response, require_https=True)

    def test_http_issuer_fails_with_default_require_https(self):
        """HTTP issuer should fail with default require_https (True)."""
        response = httpx.Response(
            200,
            json=_http_disco_json(),
            headers={"Content-Type": "application/json"},
        )
        with pytest.raises(
            ConfigurationException, match="must use HTTPS scheme"
        ):
            validate_and_parse_discovery_response(response)

    def test_https_issuer_passes_with_require_https_false(self):
        """HTTPS issuer should pass with require_https=False."""
        response = httpx.Response(
            200,
            json=_valid_disco_json(),
            headers={"Content-Type": "application/json"},
        )
        result = validate_and_parse_discovery_response(
            response, require_https=False
        )
        assert result["issuer"] == "https://example.com"

    def test_https_issuer_passes_with_require_https_true(self):
        """HTTPS issuer should pass with require_https=True."""
        response = httpx.Response(
            200,
            json=_valid_disco_json(),
            headers={"Content-Type": "application/json"},
        )
        result = validate_and_parse_discovery_response(
            response, require_https=True
        )
        assert result["issuer"] == "https://example.com"


# ============================================================================
# 3. DiscoveryDocumentRequest model
# ============================================================================


class TestDiscoveryDocumentRequestRequireHttps:
    """Tests for DiscoveryDocumentRequest.require_https field."""

    def test_default_require_https_is_true(self):
        """Default require_https should be True."""
        request = DiscoveryDocumentRequest(address="https://example.com")
        assert request.require_https is True

    def test_require_https_can_be_set_to_false(self):
        """require_https can be explicitly set to False."""
        request = DiscoveryDocumentRequest(
            address="http://localhost:8080", require_https=False
        )
        assert request.require_https is False

    def test_require_https_can_be_set_to_true(self):
        """require_https can be explicitly set to True."""
        request = DiscoveryDocumentRequest(
            address="https://example.com", require_https=True
        )
        assert request.require_https is True


# ============================================================================
# 4. TokenValidationConfig model
# ============================================================================


class TestTokenValidationConfigRequireHttps:
    """Tests for TokenValidationConfig.require_https field."""

    def test_default_require_https_is_true(self):
        """Default require_https should be True."""
        config = TokenValidationConfig(perform_disco=True)
        assert config.require_https is True

    def test_require_https_can_be_set_to_false(self):
        """require_https can be explicitly set to False."""
        config = TokenValidationConfig(perform_disco=True, require_https=False)
        assert config.require_https is False

    def test_require_https_can_be_set_to_true(self):
        """require_https can be explicitly set to True."""
        config = TokenValidationConfig(perform_disco=True, require_https=True)
        assert config.require_https is True

    def test_require_https_with_perform_disco_false(self):
        """require_https should be independent of perform_disco."""
        config = TokenValidationConfig(
            perform_disco=False,
            key={"kty": "RSA", "n": "test", "e": "AQAB"},
            algorithms=["RS256"],
            require_https=False,
        )
        assert config.require_https is False


# ============================================================================
# 5. Sync discovery flow with require_https=False
# ============================================================================


class TestSyncDiscoveryFlowRequireHttps:
    """Tests for sync discovery flow with require_https."""

    @respx.mock
    def test_sync_discovery_http_endpoint_with_require_https_false(self):
        """Sync discovery should succeed with HTTP endpoint when require_https=False."""
        from py_identity_model.sync.discovery import get_discovery_document

        url = "http://localhost:8080/.well-known/openid-configuration"
        respx.get(url).mock(
            return_value=httpx.Response(
                200,
                json=_http_disco_json(),
                headers={"Content-Type": "application/json"},
            )
        )

        request = DiscoveryDocumentRequest(address=url, require_https=False)
        result = get_discovery_document(request)

        assert result.is_successful is True
        assert result.issuer == "http://localhost:8080"

    @respx.mock
    def test_sync_discovery_http_endpoint_with_require_https_true(self):
        """Sync discovery should fail with HTTP issuer when require_https=True."""
        from py_identity_model.sync.discovery import get_discovery_document

        url = "https://example.com/.well-known/openid-configuration"
        respx.get(url).mock(
            return_value=httpx.Response(
                200,
                json=_http_disco_json(),
                headers={"Content-Type": "application/json"},
            )
        )

        request = DiscoveryDocumentRequest(address=url, require_https=True)
        result = get_discovery_document(request)

        assert result.is_successful is False
        assert result.error is not None
        assert "HTTPS" in result.error


# ============================================================================
# 5b. Async discovery flow with require_https=False
# ============================================================================


@pytest.mark.asyncio
class TestAsyncDiscoveryFlowRequireHttps:
    """Tests for async discovery flow with require_https."""

    @respx.mock
    async def test_async_discovery_http_endpoint_with_require_https_false(
        self,
    ):
        """Async discovery should succeed with HTTP endpoint when require_https=False."""
        from py_identity_model.aio.discovery import get_discovery_document

        url = "http://localhost:8080/.well-known/openid-configuration"
        respx.get(url).mock(
            return_value=httpx.Response(
                200,
                json=_http_disco_json(),
                headers={"Content-Type": "application/json"},
            )
        )

        request = DiscoveryDocumentRequest(address=url, require_https=False)
        result = await get_discovery_document(request)

        assert result.is_successful is True
        assert result.issuer == "http://localhost:8080"

    @respx.mock
    async def test_async_discovery_http_endpoint_with_require_https_true(self):
        """Async discovery should fail with HTTP issuer when require_https=True."""
        from py_identity_model.aio.discovery import get_discovery_document

        url = "https://example.com/.well-known/openid-configuration"
        respx.get(url).mock(
            return_value=httpx.Response(
                200,
                json=_http_disco_json(),
                headers={"Content-Type": "application/json"},
            )
        )

        request = DiscoveryDocumentRequest(address=url, require_https=True)
        result = await get_discovery_document(request)

        assert result.is_successful is False
        assert result.error is not None
        assert "HTTPS" in result.error


# ============================================================================
# 6. "none" response type validation
# ============================================================================


class TestNoneResponseTypeValidation:
    """Tests for 'none' response type support in validators."""

    def test_none_response_type_accepted_standalone(self):
        """'none' as a standalone response type should be accepted."""
        data = {"response_types_supported": ["none"]}
        validate_parameter_values(data)  # Should not raise

    def test_none_with_code_response_type_accepted(self):
        """'none' alongside 'code' should be accepted."""
        data = {"response_types_supported": ["code", "none"]}
        validate_parameter_values(data)  # Should not raise

    def test_none_with_all_standard_types_accepted(self):
        """'none' alongside all standard response types should be accepted."""
        data = {
            "response_types_supported": [
                "code",
                "id_token",
                "token",
                "none",
                "code id_token",
                "code token",
                "id_token token",
                "code id_token token",
            ]
        }
        validate_parameter_values(data)  # Should not raise

    def test_code_none_combined_string_rejected(self):
        """'code none' as a combined string should be rejected (invalid combo)."""
        data = {"response_types_supported": ["code none"]}
        with pytest.raises(DiscoveryException, match="Invalid response type"):
            validate_parameter_values(data)

    def test_none_token_combined_string_rejected(self):
        """'none token' as a combined string should be rejected."""
        data = {"response_types_supported": ["none token"]}
        with pytest.raises(DiscoveryException, match="Invalid response type"):
            validate_parameter_values(data)

    def test_invalid_response_type_still_rejected(self):
        """Completely invalid response types should still be rejected."""
        data = {"response_types_supported": ["invalid_type"]}
        with pytest.raises(DiscoveryException, match="Invalid response type"):
            validate_parameter_values(data)

    def test_empty_response_types_not_validated(self):
        """Empty response_types_supported list should be skipped."""
        data = {"response_types_supported": []}
        validate_parameter_values(data)  # Should not raise
