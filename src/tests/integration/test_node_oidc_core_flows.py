"""Integration tests for core OIDC/OAuth 2.0 flows against node-oidc-provider.

Tests cover:
1. Discovery & JWKS baseline
2. Client Credentials + Token Validation
3. Authorization Code + PKCE
4. Enhanced Token Validation (leeway, claims validators, issuer, expired, audience)
5. Refresh Token

Requires node-oidc-provider running on localhost:9010:
    docker compose -f test-fixtures/node-oidc-provider/docker-compose.yml up -d

Note: test_auth_code_without_pkce_fails was intentionally omitted — node-oidc-provider
v9 does not enforce PKCE for confidential clients, so this test would be a false negative.
"""

import datetime
from unittest.mock import patch

import pytest

from py_identity_model import (
    ClientCredentialsTokenRequest,
    RefreshTokenRequest,
    TokenValidationConfig,
    request_client_credentials_token,
    validate_token,
)
from py_identity_model.core.state_validation import (
    AuthorizeCallbackValidationResult,
)
from py_identity_model.exceptions import (
    TokenExpiredException,
    TokenValidationException,
)
from py_identity_model.sync.token_client import refresh_token

from .conftest import (
    AUTH_CODE_CLIENT_ID,
    AUTH_CODE_CLIENT_SECRET,
    AUTH_CODE_REDIRECT_URI,
    NODE_OIDC_ISSUER,
    perform_auth_code_flow,
)


pytestmark = pytest.mark.node_oidc


# ============================================================================
# 1. Discovery & JWKS (baseline)
# ============================================================================


class TestDiscoveryAndJWKS:
    """Verify node-oidc-provider discovery and JWKS endpoints."""

    def test_discovery_from_node_oidc(self, node_oidc_discovery):
        """Fetch discovery doc, verify issuer and endpoints."""
        assert node_oidc_discovery.is_successful
        assert node_oidc_discovery.issuer == NODE_OIDC_ISSUER
        assert node_oidc_discovery.token_endpoint is not None
        assert node_oidc_discovery.authorization_endpoint is not None
        assert node_oidc_discovery.jwks_uri is not None
        assert node_oidc_discovery.introspection_endpoint is not None

    def test_jwks_from_node_oidc(self, node_oidc_jwks):
        """Fetch JWKS, verify RSA + EC keys present."""
        assert node_oidc_jwks.is_successful
        keys = node_oidc_jwks.keys
        assert keys is not None
        assert len(keys) >= 2

        key_types = {k.kty for k in keys}
        assert "RSA" in key_types, "Expected RSA key in JWKS"
        assert "EC" in key_types, "Expected EC key in JWKS"

        # Verify key IDs
        kids = {k.kid for k in keys}
        assert "rsa-sig-key" in kids
        assert "ec-sig-key" in kids


# ============================================================================
# 2. Client Credentials + Token Validation
# ============================================================================


class TestClientCredentialsAndValidation:
    """Test client_credentials grant and JWT validation."""

    def test_client_credentials_jwt_token(self, node_oidc_cc_jwt_token):
        """Request JWT token with resource=urn:test:api, verify structure."""
        token = node_oidc_cc_jwt_token
        assert "access_token" in token
        assert token["token_type"] == "Bearer"
        assert "expires_in" in token

        # JWT tokens have 3 dot-separated segments
        access_token = token["access_token"]
        assert access_token.count(".") == 2, "Expected JWT format"

    def test_client_credentials_jwt_has_custom_claims(
        self, node_oidc_cc_jwt_token, node_oidc_jwt_key
    ):
        """Validate that JWT contains Descope-style dct/tenants claims."""
        key_dict, alg = node_oidc_jwt_key
        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=[alg],
            issuer=NODE_OIDC_ISSUER,
            options={"verify_aud": False, "require_aud": False},
        )
        decoded = validate_token(
            node_oidc_cc_jwt_token["access_token"],
            config,
        )

        # Descope-style custom claims
        assert decoded["dct"] == "test-tenant-1"
        assert "test-tenant-1" in decoded["tenants"]
        assert "test-tenant-2" in decoded["tenants"]
        assert "admin" in decoded["tenants"]["test-tenant-1"]["roles"]
        assert (
            "projects.read"
            in decoded["tenants"]["test-tenant-2"]["permissions"]
        )

    def test_client_credentials_token_without_resource(
        self, node_oidc_cc_opaque_token
    ):
        """Request token without explicit resource param, verify valid format.

        With defaultResource configured in the provider, all tokens are JWTs
        regardless of whether the client passes resource explicitly.
        """
        token = node_oidc_cc_opaque_token.token
        assert "access_token" in token
        access_token = token["access_token"]
        # Provider has defaultResource, so tokens are always JWTs
        assert access_token.count(".") == 2, "Expected JWT format"

    def test_client_credentials_invalid_client(self, node_oidc_discovery):
        """Invalid client_id/secret returns invalid_client error."""
        response = request_client_credentials_token(
            ClientCredentialsTokenRequest(
                address=node_oidc_discovery.token_endpoint,
                client_id="nonexistent-client",
                client_secret="wrong-secret",
                scope="openid",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "invalid_client" in response.error


# ============================================================================
# 3. Authorization Code + PKCE
# ============================================================================


class TestAuthCodePKCE:
    """Test authorization code + PKCE flows against devInteractions."""

    def test_auth_code_pkce_confidential_client(
        self, node_oidc_auth_code_result
    ):
        """Full auth code + PKCE flow with confidential client."""
        result = node_oidc_auth_code_result
        token_response = result["token_response"]
        assert token_response.is_successful, (
            f"Token exchange failed: {token_response.error}"
        )

        token = token_response.token
        assert "access_token" in token
        assert "refresh_token" in token  # offline_access scope requested
        assert token["token_type"] == "Bearer"

    def test_auth_code_pkce_public_client(
        self, node_oidc_public_auth_code_result
    ):
        """Full auth code + PKCE flow with public client (no client_secret)."""
        result = node_oidc_public_auth_code_result
        token_response = result["token_response"]
        assert token_response.is_successful, (
            f"Token exchange failed: {token_response.error}"
        )

        token = token_response.token
        assert "access_token" in token
        assert token["token_type"] == "Bearer"

    def test_auth_code_callback_state_validation(
        self, node_oidc_auth_code_result
    ):
        """Verify state parameter roundtrip."""
        result = node_oidc_auth_code_result
        assert result["state_result"].is_valid
        # State in callback matches the one we sent
        assert result["callback"].state == result["state"]

    def test_auth_code_callback_state_mismatch(
        self, node_oidc_auth_code_result
    ):
        """Wrong state returns STATE_MISMATCH."""
        from py_identity_model import validate_authorize_callback_state

        callback = node_oidc_auth_code_result["callback"]
        wrong_state = "completely-wrong-state-value"
        state_result = validate_authorize_callback_state(callback, wrong_state)
        assert not state_result.is_valid
        assert (
            state_result.result
            == AuthorizeCallbackValidationResult.STATE_MISMATCH
        )

    def test_auth_code_invalid_code_verifier(self, node_oidc_discovery):
        """Wrong code_verifier fails token exchange with invalid_grant error."""
        import secrets

        from py_identity_model import (
            AuthorizationCodeTokenRequest,
            request_authorization_code_token,
        )

        # Submit a fabricated auth code with a wrong verifier.
        # The token endpoint should reject with invalid_grant.
        wrong_verifier = "wrong-verifier-" + secrets.token_urlsafe(32)
        token_response = request_authorization_code_token(
            AuthorizationCodeTokenRequest(
                address=node_oidc_discovery.token_endpoint,
                client_id=AUTH_CODE_CLIENT_ID,
                code="invalid-authorization-code",
                redirect_uri=AUTH_CODE_REDIRECT_URI,
                code_verifier=wrong_verifier,
                client_secret=AUTH_CODE_CLIENT_SECRET,
            )
        )
        assert token_response.is_successful is False
        assert token_response.error is not None
        assert "invalid_grant" in token_response.error


# ============================================================================
# 4. Enhanced Token Validation
# ============================================================================


class TestTokenValidation:
    """Test JWT validation features against real tokens from node-oidc-provider."""

    def test_validate_jwt_manual_key(
        self, node_oidc_cc_jwt_token, node_oidc_jwt_key
    ):
        """Validate JWT with manually-provided key (HTTP fixture can't use auto-discovery)."""
        key_dict, alg = node_oidc_jwt_key
        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=[alg],
            issuer=NODE_OIDC_ISSUER,
            options={"verify_aud": False, "require_aud": False},
        )
        decoded = validate_token(
            node_oidc_cc_jwt_token["access_token"],
            config,
        )
        assert "iss" in decoded
        assert decoded["iss"] == NODE_OIDC_ISSUER

    def test_validate_jwt_with_leeway(
        self, node_oidc_cc_jwt_token, node_oidc_jwt_key
    ):
        """Token validation with clock skew tolerance."""
        key_dict, alg = node_oidc_jwt_key
        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=[alg],
            issuer=NODE_OIDC_ISSUER,
            leeway=60,
            options={"verify_aud": False, "require_aud": False},
        )
        decoded = validate_token(
            node_oidc_cc_jwt_token["access_token"],
            config,
        )
        assert "exp" in decoded
        assert "iat" in decoded

    def test_validate_jwt_custom_claims_validator(
        self, node_oidc_cc_jwt_token, node_oidc_jwt_key
    ):
        """Custom claims validator checks dct/tenants."""

        def validate_descope_claims(claims: dict) -> None:
            if "dct" not in claims:
                raise ValueError("Missing dct claim")
            if "tenants" not in claims:
                raise ValueError("Missing tenants claim")
            tenant_id = claims["dct"]
            if tenant_id not in claims["tenants"]:
                raise ValueError(f"dct tenant {tenant_id} not in tenants")

        key_dict, alg = node_oidc_jwt_key
        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=[alg],
            issuer=NODE_OIDC_ISSUER,
            claims_validator=validate_descope_claims,
            options={"verify_aud": False, "require_aud": False},
        )
        decoded = validate_token(
            node_oidc_cc_jwt_token["access_token"],
            config,
        )
        assert decoded["dct"] == "test-tenant-1"

    def test_validate_jwt_claims_validator_rejects(
        self, node_oidc_cc_jwt_token, node_oidc_jwt_key
    ):
        """Claims validator raises -> TokenValidationException."""

        def reject_all(claims: dict) -> None:
            raise ValueError("Rejected by policy")

        key_dict, alg = node_oidc_jwt_key
        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=[alg],
            issuer=NODE_OIDC_ISSUER,
            claims_validator=reject_all,
            options={"verify_aud": False, "require_aud": False},
        )
        with pytest.raises(
            TokenValidationException, match="Rejected by policy"
        ):
            validate_token(
                node_oidc_cc_jwt_token["access_token"],
                config,
            )

    def test_validate_wrong_issuer(
        self, node_oidc_cc_jwt_token, node_oidc_jwt_key
    ):
        """Token with wrong issuer config fails."""
        key_dict, alg = node_oidc_jwt_key
        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=[alg],
            issuer="https://wrong-issuer.example.com",
            options={"verify_aud": False, "require_aud": False},
        )
        with pytest.raises(TokenValidationException):
            validate_token(node_oidc_cc_jwt_token["access_token"], config)

    def test_validate_auth_code_jwt_token(
        self, node_oidc_auth_code_result, node_oidc_jwt_key
    ):
        """Validate JWT obtained from auth code flow."""
        token_response = node_oidc_auth_code_result["token_response"]
        access_token = token_response.token["access_token"]

        # Auth code tokens with resource=urn:test:api must be JWTs
        assert access_token.count(".") == 2, (
            "Expected JWT but got opaque token"
        )

        key_dict, alg = node_oidc_jwt_key
        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=[alg],
            issuer=NODE_OIDC_ISSUER,
            options={"verify_aud": False, "require_aud": False},
        )
        decoded = validate_token(
            access_token,
            config,
        )
        assert decoded["iss"] == NODE_OIDC_ISSUER
        assert "sub" in decoded

    def test_validate_expired_token(
        self, node_oidc_cc_jwt_token, node_oidc_jwt_key
    ):
        """Expired token raises TokenExpiredException.

        Uses a real provider-issued JWT but patches time forward so PyJWT
        sees it as expired. This validates the library's exp->TokenExpiredException
        mapping end-to-end with a real token.
        """
        key_dict, alg = node_oidc_jwt_key
        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=[alg],
            issuer=NODE_OIDC_ISSUER,
            leeway=0,
            options={
                "verify_aud": False,
                "require_aud": False,
                "verify_exp": True,
            },
        )

        # Patch datetime.now in PyJWT's module to return a date far in the future
        # so the fresh token appears expired. This forces exp validation to fail.
        far_future = datetime.datetime(2099, 1, 1, tzinfo=datetime.UTC)
        with patch("jwt.api_jwt.datetime") as mock_dt:
            mock_dt.now.return_value = far_future
            mock_dt.timezone = datetime.timezone
            with pytest.raises(TokenExpiredException):
                validate_token(
                    node_oidc_cc_jwt_token["access_token"],
                    config,
                )

    def test_validate_wrong_audience(
        self, node_oidc_cc_jwt_token, node_oidc_jwt_key
    ):
        """Token with wrong audience claim is rejected.

        Verifies that audience validation works against a real provider token.
        """
        key_dict, alg = node_oidc_jwt_key
        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=[alg],
            issuer=NODE_OIDC_ISSUER,
            audience="https://wrong-audience.example.com",
            options={"verify_aud": True, "require_aud": True},
        )
        with pytest.raises(TokenValidationException):
            validate_token(node_oidc_cc_jwt_token["access_token"], config)


# ============================================================================
# 5. Refresh Token
# ============================================================================


class TestRefreshToken:
    """Test refresh token grant after auth code flow.

    Each test performs its own auth code flow to get a fresh refresh token,
    avoiding order-dependent flaky failures from oidc-provider's refresh
    token rotation (consuming a refresh token invalidates it).
    """

    def _get_fresh_tokens(self, node_oidc_discovery) -> dict:
        """Perform a fresh auth code flow and return the token dict."""
        result = perform_auth_code_flow(
            discovery=node_oidc_discovery,
            client_id=AUTH_CODE_CLIENT_ID,
            redirect_uri=AUTH_CODE_REDIRECT_URI,
            client_secret=AUTH_CODE_CLIENT_SECRET,
            scope="openid profile email offline_access",
        )
        token_response = result["token_response"]
        assert token_response.is_successful, (
            f"Auth code flow failed: {token_response.error}"
        )
        token = token_response.token
        assert "refresh_token" in token, (
            "No refresh_token — offline_access not granted?"
        )
        return token

    def test_refresh_token_success(self, node_oidc_discovery):
        """Get tokens via auth code, then refresh."""
        token = self._get_fresh_tokens(node_oidc_discovery)

        response = refresh_token(
            RefreshTokenRequest(
                address=node_oidc_discovery.token_endpoint,
                client_id=AUTH_CODE_CLIENT_ID,
                refresh_token=token["refresh_token"],
                client_secret=AUTH_CODE_CLIENT_SECRET,
            )
        )
        assert response.is_successful, f"Refresh failed: {response.error}"
        assert response.token is not None
        assert "access_token" in response.token

    def test_refresh_token_returns_new_access_token(self, node_oidc_discovery):
        """New access_token differs from original."""
        original_token = self._get_fresh_tokens(node_oidc_discovery)

        response = refresh_token(
            RefreshTokenRequest(
                address=node_oidc_discovery.token_endpoint,
                client_id=AUTH_CODE_CLIENT_ID,
                refresh_token=original_token["refresh_token"],
                client_secret=AUTH_CODE_CLIENT_SECRET,
            )
        )
        assert response.is_successful
        assert response.token is not None
        # New access token should be different
        assert response.token["access_token"] != original_token["access_token"]

    def test_refresh_token_invalid(self, node_oidc_discovery):
        """Invalid refresh token returns invalid_grant error."""
        response = refresh_token(
            RefreshTokenRequest(
                address=node_oidc_discovery.token_endpoint,
                client_id=AUTH_CODE_CLIENT_ID,
                refresh_token="invalid-refresh-token-value",
                client_secret=AUTH_CODE_CLIENT_SECRET,
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "invalid_grant" in response.error

    def test_refresh_token_scope_downscope(self, node_oidc_discovery):
        """Refresh with reduced scope."""
        original_token = self._get_fresh_tokens(node_oidc_discovery)

        response = refresh_token(
            RefreshTokenRequest(
                address=node_oidc_discovery.token_endpoint,
                client_id=AUTH_CODE_CLIENT_ID,
                refresh_token=original_token["refresh_token"],
                client_secret=AUTH_CODE_CLIENT_SECRET,
                scope="openid",  # Request subset of original scopes
            )
        )
        assert response.is_successful, (
            f"Downscoped refresh failed: {response.error}"
        )
        assert response.token is not None
        assert "access_token" in response.token
