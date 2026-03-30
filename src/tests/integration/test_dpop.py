"""Integration tests for DPoP (RFC 9449)."""

import jwt as pyjwt
import pytest

from py_identity_model.core.dpop import (
    build_dpop_headers,
    compute_ath,
    create_dpop_proof,
    generate_dpop_key,
)


@pytest.mark.integration
class TestDPoPIntegration:
    def test_full_token_request_flow(self):
        """Generate key, create proof for token endpoint."""
        key = generate_dpop_key()
        proof = create_dpop_proof(
            key, "POST", "https://auth.example.com/token"
        )
        headers = build_dpop_headers(proof)

        assert "DPoP" in headers
        # Verify proof is valid JWT
        decoded = pyjwt.decode(proof, options={"verify_signature": False})
        assert decoded["htm"] == "POST"

    def test_full_resource_request_flow(self):
        """Generate key, create proof with ath for resource server."""
        key = generate_dpop_key()
        access_token = "eyJhbGciOi..."
        proof = create_dpop_proof(
            key,
            "GET",
            "https://api.example.com/resource",
            access_token=access_token,
        )
        headers = build_dpop_headers(proof, access_token)

        assert headers["Authorization"] == f"DPoP {access_token}"
        decoded = pyjwt.decode(proof, options={"verify_signature": False})
        assert decoded["ath"] == compute_ath(access_token)

    def test_dpop_jkt_for_authorization_request(self):
        """Generate dpop_jkt parameter for authorization URL."""
        key = generate_dpop_key()
        jkt = key.jwk_thumbprint
        assert len(jkt) > 20  # Base64url SHA-256 hash
