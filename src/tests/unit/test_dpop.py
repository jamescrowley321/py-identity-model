"""Unit tests for DPoP (RFC 9449) utilities."""

import jwt as pyjwt
import pytest

from py_identity_model.core.dpop import (
    build_dpop_headers,
    compute_ath,
    create_dpop_proof,
    generate_dpop_key,
)


@pytest.mark.unit
class TestDPoPKeyGeneration:
    def test_es256_default(self):
        key = generate_dpop_key()
        assert key.algorithm == "ES256"

    def test_rs256(self):
        key = generate_dpop_key("RS256")
        assert key.algorithm == "RS256"

    def test_unsupported_algorithm(self):
        with pytest.raises(ValueError, match="Unsupported"):
            generate_dpop_key("HS256")

    def test_public_jwk_ec(self):
        key = generate_dpop_key("ES256")
        jwk = key.public_jwk
        assert jwk["kty"] == "EC"
        assert jwk["crv"] == "P-256"
        assert "x" in jwk
        assert "y" in jwk

    def test_public_jwk_rsa(self):
        key = generate_dpop_key("RS256")
        jwk = key.public_jwk
        assert jwk["kty"] == "RSA"
        assert "n" in jwk
        assert "e" in jwk

    def test_jwk_thumbprint_deterministic(self):
        key = generate_dpop_key()
        t1 = key.jwk_thumbprint
        t2 = key.jwk_thumbprint
        assert t1 == t2

    def test_jwk_thumbprint_unique_per_key(self):
        k1 = generate_dpop_key()
        k2 = generate_dpop_key()
        assert k1.jwk_thumbprint != k2.jwk_thumbprint

    def test_private_key_pem(self):
        key = generate_dpop_key()
        pem = key.private_key_pem
        assert pem.startswith(b"-----BEGIN PRIVATE KEY-----")


@pytest.mark.unit
class TestDPoPProofCreation:
    def test_basic_proof(self):
        key = generate_dpop_key()
        proof = create_dpop_proof(
            key, "POST", "https://auth.example.com/token"
        )

        decoded = pyjwt.decode(proof, options={"verify_signature": False})
        assert decoded["htm"] == "POST"
        assert decoded["htu"] == "https://auth.example.com/token"
        assert "jti" in decoded
        assert "iat" in decoded

    def test_proof_header(self):
        key = generate_dpop_key()
        proof = create_dpop_proof(
            key, "GET", "https://api.example.com/resource"
        )

        header = pyjwt.get_unverified_header(proof)
        assert header["typ"] == "dpop+jwt"
        assert header["alg"] == "ES256"
        assert "jwk" in header
        assert header["jwk"]["kty"] == "EC"

    def test_proof_with_access_token(self):
        key = generate_dpop_key()
        proof = create_dpop_proof(
            key,
            "GET",
            "https://api.example.com/resource",
            access_token="my_access_token",
        )

        decoded = pyjwt.decode(proof, options={"verify_signature": False})
        assert "ath" in decoded
        assert decoded["ath"] == compute_ath("my_access_token")

    def test_proof_with_nonce(self):
        key = generate_dpop_key()
        proof = create_dpop_proof(
            key,
            "POST",
            "https://auth.example.com/token",
            nonce="server_nonce_123",
        )

        decoded = pyjwt.decode(proof, options={"verify_signature": False})
        assert decoded["nonce"] == "server_nonce_123"

    def test_proof_method_uppercased(self):
        key = generate_dpop_key()
        proof = create_dpop_proof(
            key, "post", "https://auth.example.com/token"
        )

        decoded = pyjwt.decode(proof, options={"verify_signature": False})
        assert decoded["htm"] == "POST"

    def test_unique_jti(self):
        key = generate_dpop_key()
        p1 = create_dpop_proof(key, "POST", "https://auth.example.com/token")
        p2 = create_dpop_proof(key, "POST", "https://auth.example.com/token")

        d1 = pyjwt.decode(p1, options={"verify_signature": False})
        d2 = pyjwt.decode(p2, options={"verify_signature": False})
        assert d1["jti"] != d2["jti"]


@pytest.mark.unit
class TestComputeAth:
    def test_deterministic(self):
        assert compute_ath("token123") == compute_ath("token123")

    def test_different_tokens(self):
        assert compute_ath("token1") != compute_ath("token2")

    def test_base64url_no_padding(self):
        ath = compute_ath("test")
        assert "=" not in ath


@pytest.mark.unit
class TestBuildDPoPHeaders:
    def test_token_request_headers(self):
        headers = build_dpop_headers("proof_jwt")
        assert headers["DPoP"] == "proof_jwt"
        assert "Authorization" not in headers

    def test_resource_request_headers(self):
        headers = build_dpop_headers("proof_jwt", "my_token")
        assert headers["DPoP"] == "proof_jwt"
        assert headers["Authorization"] == "DPoP my_token"
