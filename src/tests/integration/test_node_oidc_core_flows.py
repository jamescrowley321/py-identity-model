"""Integration tests for core OIDC/OAuth 2.0 flows against node-oidc-provider.

Tests cover:
1. Discovery & JWKS baseline
2. Client Credentials + Token Validation
3. Authorization Code + PKCE
4. Enhanced Token Validation (leeway, claims validators, issuer)
5. Refresh Token

Requires node-oidc-provider running on localhost:9010:
    docker compose -f test-fixtures/node-oidc-provider/docker-compose.yml up -d
"""

import secrets
from urllib.parse import urlencode

import httpx
import pytest

from py_identity_model import (
    AuthorizationCodeTokenRequest,
    ClientCredentialsTokenRequest,
    DiscoveryDocumentRequest,
    JwksRequest,
    RefreshTokenRequest,
    TokenValidationConfig,
    get_discovery_document,
    get_jwks,
    parse_authorize_callback_response,
    request_authorization_code_token,
    request_client_credentials_token,
    validate_token,
)
from py_identity_model.core.parsers import (
    extract_kid_from_jwt,
    find_key_by_kid,
)
from py_identity_model.core.pkce import generate_pkce_pair
from py_identity_model.core.state_validation import (
    AuthorizeCallbackValidationResult,
)
from py_identity_model.exceptions import TokenValidationException
from py_identity_model.sync.token_client import refresh_token

from .conftest_node_oidc import (
    AUTH_CODE_CLIENT_ID,
    AUTH_CODE_CLIENT_SECRET,
    AUTH_CODE_REDIRECT_URI,
    NODE_OIDC_BASE_URL,
    NODE_OIDC_DISCO_URL,
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
        assert node_oidc_discovery.issuer == "http://localhost:9010"
        assert node_oidc_discovery.token_endpoint is not None
        assert node_oidc_discovery.authorization_endpoint is not None
        assert node_oidc_discovery.jwks_uri is not None
        assert node_oidc_discovery.introspection_endpoint is not None
        assert node_oidc_discovery.revocation_endpoint is not None

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
        self, node_oidc_cc_jwt_token
    ):
        """Validate that JWT contains Descope-style dct/tenants claims."""
        config = TokenValidationConfig(
            perform_disco=True,
            options={"verify_aud": False, "require_aud": False},
        )
        decoded = validate_token(
            node_oidc_cc_jwt_token["access_token"],
            config,
            disco_doc_address=NODE_OIDC_DISCO_URL,
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

    def test_client_credentials_opaque_token(self, node_oidc_cc_opaque_token):
        """Request opaque token (no resource param), verify non-JWT format."""
        token = node_oidc_cc_opaque_token.token
        assert "access_token" in token
        access_token = token["access_token"]
        # Opaque tokens do NOT have 3 dot-separated segments
        assert access_token.count(".") != 2, "Expected opaque, not JWT"

    def test_client_credentials_invalid_client(self, node_oidc_discovery):
        """Invalid client_id/secret returns error."""
        response = request_client_credentials_token(
            ClientCredentialsTokenRequest(
                address=node_oidc_discovery.token_endpoint,
                client_id="nonexistent-client",
                client_secret="wrong-secret",
                scope="openid",
            )
        )
        assert response.is_successful is False


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
        """Wrong code_verifier fails token exchange."""
        _verifier, code_challenge = generate_pkce_pair()
        state = secrets.token_urlsafe(32)

        auth_params = {
            "client_id": AUTH_CODE_CLIENT_ID,
            "redirect_uri": AUTH_CODE_REDIRECT_URI,
            "response_type": "code",
            "scope": "openid",
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        auth_url = (
            f"{node_oidc_discovery.authorization_endpoint}"
            f"?{urlencode(auth_params)}"
        )

        # Navigate devInteractions to get an auth code
        callback_url = None
        with httpx.Client(follow_redirects=False, timeout=10.0) as client:
            resp = client.get(auth_url)
            while resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers["location"]
                if not location.startswith("http"):
                    location = f"{NODE_OIDC_BASE_URL}{location}"
                if location.startswith(AUTH_CODE_REDIRECT_URI):
                    callback_url = location
                    break
                resp = client.get(location)

            if callback_url is None:
                # Login step
                interaction_url = str(resp.url)
                resp = client.post(
                    f"{interaction_url}/login",
                    data={"login": "test-user", "password": "test"},
                )
                while resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers["location"]
                    if not location.startswith("http"):
                        location = f"{NODE_OIDC_BASE_URL}{location}"
                    if location.startswith(AUTH_CODE_REDIRECT_URI):
                        callback_url = location
                        break
                    resp = client.get(location)

            # Consent step if needed
            if callback_url is None and "/interaction/" in str(resp.url):
                resp = client.post(f"{resp.url}/confirm")
                while resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers["location"]
                    if not location.startswith("http"):
                        location = f"{NODE_OIDC_BASE_URL}{location}"
                    if location.startswith(AUTH_CODE_REDIRECT_URI):
                        callback_url = location
                        break
                    resp = client.get(location)

        assert callback_url is not None, "Failed to get callback URL"
        callback = parse_authorize_callback_response(callback_url)
        assert callback.is_successful

        # Exchange code with WRONG code_verifier
        assert callback.code is not None
        wrong_verifier = "wrong-verifier-" + secrets.token_urlsafe(32)
        token_response = request_authorization_code_token(
            AuthorizationCodeTokenRequest(
                address=node_oidc_discovery.token_endpoint,
                client_id=AUTH_CODE_CLIENT_ID,
                code=callback.code,
                redirect_uri=AUTH_CODE_REDIRECT_URI,
                code_verifier=wrong_verifier,
                client_secret=AUTH_CODE_CLIENT_SECRET,
            )
        )
        assert token_response.is_successful is False


# ============================================================================
# 4. Enhanced Token Validation
# ============================================================================


class TestTokenValidation:
    """Test JWT validation features against real tokens from node-oidc-provider."""

    def test_validate_jwt_with_discovery(self, node_oidc_cc_jwt_token):
        """Standard validation with auto-discovery."""
        config = TokenValidationConfig(
            perform_disco=True,
            options={"verify_aud": False, "require_aud": False},
        )
        decoded = validate_token(
            node_oidc_cc_jwt_token["access_token"],
            config,
            disco_doc_address=NODE_OIDC_DISCO_URL,
        )
        assert "iss" in decoded
        assert decoded["iss"] == "http://localhost:9010"

    def test_validate_jwt_with_leeway(self, node_oidc_cc_jwt_token):
        """Token validation with clock skew tolerance."""
        config = TokenValidationConfig(
            perform_disco=True,
            leeway=60,
            options={"verify_aud": False, "require_aud": False},
        )
        decoded = validate_token(
            node_oidc_cc_jwt_token["access_token"],
            config,
            disco_doc_address=NODE_OIDC_DISCO_URL,
        )
        assert "exp" in decoded
        assert "iat" in decoded

    def test_validate_jwt_custom_claims_validator(
        self, node_oidc_cc_jwt_token
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

        config = TokenValidationConfig(
            perform_disco=True,
            claims_validator=validate_descope_claims,
            options={"verify_aud": False, "require_aud": False},
        )
        decoded = validate_token(
            node_oidc_cc_jwt_token["access_token"],
            config,
            disco_doc_address=NODE_OIDC_DISCO_URL,
        )
        assert decoded["dct"] == "test-tenant-1"

    def test_validate_jwt_claims_validator_rejects(
        self, node_oidc_cc_jwt_token
    ):
        """Claims validator raises -> TokenValidationException."""

        def reject_all(claims: dict) -> None:
            raise ValueError("Rejected by policy")

        config = TokenValidationConfig(
            perform_disco=True,
            claims_validator=reject_all,
            options={"verify_aud": False, "require_aud": False},
        )
        with pytest.raises(
            TokenValidationException, match="Rejected by policy"
        ):
            validate_token(
                node_oidc_cc_jwt_token["access_token"],
                config,
                disco_doc_address=NODE_OIDC_DISCO_URL,
            )

    def test_validate_wrong_issuer(self, node_oidc_cc_jwt_token):
        """Token with wrong issuer config fails."""
        disco = get_discovery_document(
            DiscoveryDocumentRequest(address=NODE_OIDC_DISCO_URL)
        )
        assert disco.jwks_uri is not None
        jwks = get_jwks(JwksRequest(address=disco.jwks_uri))
        jwt_token = node_oidc_cc_jwt_token["access_token"]
        kid = extract_kid_from_jwt(jwt_token)
        key_dict, alg = find_key_by_kid(kid, jwks.keys or [])

        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=[alg],
            issuer="https://wrong-issuer.example.com",
            options={"verify_aud": False, "require_aud": False},
        )
        with pytest.raises(TokenValidationException):
            validate_token(jwt_token, config)

    def test_validate_auth_code_jwt_token(self, node_oidc_auth_code_result):
        """Validate JWT obtained from auth code flow."""
        token_response = node_oidc_auth_code_result["token_response"]
        access_token = token_response.token["access_token"]

        # Auth code tokens with resource=urn:test:api should be JWTs
        if access_token.count(".") == 2:
            config = TokenValidationConfig(
                perform_disco=True,
                options={"verify_aud": False, "require_aud": False},
            )
            decoded = validate_token(
                access_token,
                config,
                disco_doc_address=NODE_OIDC_DISCO_URL,
            )
            assert decoded["iss"] == "http://localhost:9010"
            assert "sub" in decoded


# ============================================================================
# 5. Refresh Token
# ============================================================================


class TestRefreshToken:
    """Test refresh token grant after auth code flow."""

    def test_refresh_token_success(
        self, node_oidc_auth_code_result, node_oidc_discovery
    ):
        """Get tokens via auth code, then refresh."""
        token = node_oidc_auth_code_result["token_response"].token
        assert "refresh_token" in token, (
            "No refresh_token — offline_access not granted?"
        )

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

    def test_refresh_token_returns_new_access_token(
        self, node_oidc_auth_code_result, node_oidc_discovery
    ):
        """New access_token differs from original."""
        original_token = node_oidc_auth_code_result["token_response"].token
        assert "refresh_token" in original_token

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
        """Invalid refresh token returns error."""
        response = refresh_token(
            RefreshTokenRequest(
                address=node_oidc_discovery.token_endpoint,
                client_id=AUTH_CODE_CLIENT_ID,
                refresh_token="invalid-refresh-token-value",
                client_secret=AUTH_CODE_CLIENT_SECRET,
            )
        )
        assert response.is_successful is False

    def test_refresh_token_scope_downscope(
        self, node_oidc_auth_code_result, node_oidc_discovery
    ):
        """Refresh with reduced scope."""
        original_token = node_oidc_auth_code_result["token_response"].token
        assert "refresh_token" in original_token

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
