"""Integration tests for DPoP (RFC 9449), PAR (RFC 9126), and JAR (RFC 9101).

These tests hit a live OIDC provider.  Each test is gated on the
relevant provider capability detected from the discovery document.
"""

import secrets

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
import jwt as pyjwt
import pytest

from py_identity_model import (
    PushedAuthorizationRequest,
    build_jar_authorization_url,
    create_request_object,
    generate_pkce_pair,
    push_authorization_request,
)
from py_identity_model.core.dpop import (
    build_dpop_headers,
    create_dpop_proof,
    generate_dpop_key,
)
from py_identity_model.sync.managed_client import HTTPClient

from .conftest import HTTP_BAD_REQUEST, HTTP_OK


# HTTP 401 Unauthorized
HTTP_UNAUTHORIZED = 401


# ============================================================================
# PAR (RFC 9126) — requires "par" capability
# ============================================================================


@pytest.mark.integration
class TestPARLive:
    """Test Pushed Authorization Requests against a live provider."""

    def test_par_success(
        self,
        provider_capabilities,
        raw_discovery,
        test_config,
    ):
        """Push authorization parameters and receive request_uri."""
        if "par" not in provider_capabilities:
            pytest.skip("Provider does not support PAR")

        endpoint = raw_discovery["pushed_authorization_request_endpoint"]
        _verifier, challenge = generate_pkce_pair()

        auth_code_client_id = test_config.get("TEST_AUTH_CODE_CLIENT_ID")
        auth_code_client_secret = test_config.get("TEST_AUTH_CODE_CLIENT_SECRET")
        if not auth_code_client_id:
            pytest.skip("TEST_AUTH_CODE_CLIENT_ID not configured")

        response = push_authorization_request(
            PushedAuthorizationRequest(
                address=endpoint,
                client_id=auth_code_client_id,
                redirect_uri=test_config.get(
                    "TEST_AUTH_CODE_REDIRECT_URI", "https://localhost/callback"
                ),
                scope="openid",
                code_challenge=challenge,
                code_challenge_method="S256",
                state=secrets.token_urlsafe(32),
                client_secret=auth_code_client_secret,
            )
        )

        assert response.is_successful is True, f"PAR failed: {response.error}"
        assert response.request_uri is not None
        assert response.request_uri.startswith("urn:ietf:params:oauth:request_uri:")
        assert response.expires_in is not None
        assert response.expires_in > 0

    def test_par_invalid_client(
        self,
        provider_capabilities,
        raw_discovery,
    ):
        """PAR with invalid client credentials returns error."""
        if "par" not in provider_capabilities:
            pytest.skip("Provider does not support PAR")

        endpoint = raw_discovery["pushed_authorization_request_endpoint"]

        response = push_authorization_request(
            PushedAuthorizationRequest(
                address=endpoint,
                client_id="nonexistent-client",
                redirect_uri="https://localhost/callback",
                client_secret="wrong-secret",
            )
        )

        assert response.is_successful is False
        assert response.error is not None


# ============================================================================
# DPoP (RFC 9449) — requires "dpop" capability
# ============================================================================


@pytest.mark.integration
class TestDPoPLive:
    """Test DPoP proofs with a live token endpoint."""

    def test_token_request_with_dpop_proof(
        self,
        provider_capabilities,
        token_endpoint,
        test_config,
    ):
        """Request a token with a DPoP proof header attached."""
        if "dpop" not in provider_capabilities:
            pytest.skip("Provider does not support DPoP")

        key = generate_dpop_key()
        proof = create_dpop_proof(key, "POST", token_endpoint)
        dpop_headers = build_dpop_headers(proof)

        with HTTPClient() as managed:
            resp = managed.client.post(
                token_endpoint,
                data={
                    "grant_type": "client_credentials",
                    "client_id": test_config["TEST_CLIENT_ID"],
                    "client_secret": test_config["TEST_CLIENT_SECRET"],
                    "scope": test_config.get("TEST_SCOPE", "openid"),
                },
                headers=dpop_headers,
            )

        # DPoP-aware providers should accept or return a specific error
        # (not a generic 400 "unsupported_token_type").  The exact
        # behaviour depends on the provider's DPoP enforcement mode.
        assert resp.status_code in (HTTP_OK, HTTP_BAD_REQUEST, HTTP_UNAUTHORIZED)
        if resp.status_code == HTTP_OK:
            data = resp.json()
            assert "access_token" in data
            # Provider may indicate DPoP-bound token
            assert data.get("token_type") in ("Bearer", "DPoP")

    def test_dpop_proof_structure(self):
        """Verify DPoP proof JWT structure matches RFC 9449."""
        key = generate_dpop_key()
        proof = create_dpop_proof(key, "POST", "https://auth.example.com/token")

        header = pyjwt.get_unverified_header(proof)
        assert header["typ"] == "dpop+jwt"
        assert header["alg"] == "ES256"
        assert "jwk" in header

        decoded = pyjwt.decode(proof, options={"verify_signature": False})
        assert decoded["htm"] == "POST"
        assert decoded["htu"] == "https://auth.example.com/token"
        assert "jti" in decoded
        assert "iat" in decoded


# ============================================================================
# JAR (RFC 9101) — requires "jar" capability
# ============================================================================


@pytest.mark.integration
class TestJARLive:
    """Test JAR request objects with a live provider."""

    def test_jar_authorization_url(
        self,
        provider_capabilities,
        discovery_document,
    ):
        """Build JAR authorization URL and verify structure."""
        if "jar" not in provider_capabilities:
            pytest.skip("Provider does not support JAR")

        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        _verifier, challenge = generate_pkce_pair()

        request_jwt = create_request_object(
            private_key=pem,
            algorithm="ES256",
            client_id="jar-integration-test",
            audience=discovery_document.issuer,
            redirect_uri="https://localhost/callback",
            scope="openid",
            code_challenge=challenge,
            code_challenge_method="S256",
        )

        url = build_jar_authorization_url(
            authorization_endpoint=discovery_document.authorization_endpoint,
            client_id="jar-integration-test",
            request_object=request_jwt,
        )

        assert discovery_document.authorization_endpoint in url
        assert "request=" in url

    def test_jar_with_par(
        self,
        provider_capabilities,
        raw_discovery,
        test_config,
    ):
        """Combine JAR request object with PAR endpoint."""
        if "jar" not in provider_capabilities:
            pytest.skip("Provider does not support JAR")
        if "par" not in provider_capabilities:
            pytest.skip("Provider does not support PAR")

        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())

        request_jwt = create_request_object(
            private_key=pem,
            algorithm="ES256",
            client_id=test_config["TEST_CLIENT_ID"],
            audience=raw_discovery.get("issuer", ""),
            redirect_uri=test_config.get(
                "TEST_AUTH_CODE_REDIRECT_URI", "https://localhost/callback"
            ),
            scope="openid",
        )

        endpoint = raw_discovery["pushed_authorization_request_endpoint"]

        with HTTPClient() as managed:
            resp = managed.client.post(
                endpoint,
                data={
                    "client_id": test_config["TEST_CLIENT_ID"],
                    "client_secret": test_config.get("TEST_CLIENT_SECRET", ""),
                    "request": request_jwt,
                },
            )

        # Provider may accept or reject — the test verifies
        # the round-trip doesn't crash
        assert resp.status_code in (200, 201, 400, 401)
