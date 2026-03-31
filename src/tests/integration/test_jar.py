"""Integration tests for JWT Secured Authorization Request (JAR, RFC 9101)."""

from urllib.parse import parse_qs, urlparse

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
import jwt as pyjwt
import pytest

from py_identity_model import (
    build_jar_authorization_url,
    create_request_object,
    generate_pkce_pair,
)


@pytest.mark.integration
class TestJARIntegration:
    def test_full_flow_ec256(self):
        """Create request object with EC key, build URL, verify JWT."""
        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        pub_pem = key.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        )

        request_jwt = create_request_object(
            private_key=pem,
            algorithm="ES256",
            client_id="integration-app",
            audience="https://auth.example.com",
            redirect_uri="https://app.com/callback",
            scope="openid profile",
            state="test-state",
        )

        # Verify signature with public key
        decoded = pyjwt.decode(
            request_jwt,
            pub_pem,
            algorithms=["ES256"],
            audience="https://auth.example.com",
        )
        assert decoded["iss"] == "integration-app"
        assert decoded["scope"] == "openid profile"
        assert decoded["state"] == "test-state"

    def test_full_flow_rsa256(self):
        """Create request object with RSA key, build URL, verify JWT."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        pub_pem = key.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        )

        request_jwt = create_request_object(
            private_key=pem,
            algorithm="RS256",
            client_id="rsa-app",
            audience="https://auth.example.com",
            redirect_uri="https://app.com/callback",
        )

        decoded = pyjwt.decode(
            request_jwt,
            pub_pem,
            algorithms=["RS256"],
            audience="https://auth.example.com",
        )
        assert decoded["iss"] == "rsa-app"
        assert decoded["response_type"] == "code"

    def test_jar_with_pkce(self):
        """Combine JAR with PKCE code challenge."""
        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        pub_pem = key.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        )
        _verifier, challenge = generate_pkce_pair()

        request_jwt = create_request_object(
            private_key=pem,
            algorithm="ES256",
            client_id="pkce-app",
            audience="https://auth.example.com",
            redirect_uri="https://app.com/cb",
            code_challenge=challenge,
            code_challenge_method="S256",
        )

        decoded = pyjwt.decode(
            request_jwt,
            pub_pem,
            algorithms=["ES256"],
            audience="https://auth.example.com",
        )
        assert decoded["code_challenge"] == challenge
        assert decoded["code_challenge_method"] == "S256"

    def test_build_url_with_real_jwt(self):
        """Build authorization URL containing actual signed JWT."""
        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        pub_pem = key.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        )

        request_jwt = create_request_object(
            private_key=pem,
            algorithm="ES256",
            client_id="url-app",
            audience="https://auth.example.com",
            redirect_uri="https://app.com/cb",
        )

        url = build_jar_authorization_url(
            authorization_endpoint="https://auth.example.com/authorize",
            client_id="url-app",
            request_object=request_jwt,
            scope="openid",
            response_type="code",
        )

        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        assert params["client_id"] == ["url-app"]

        # Extract and verify JWT signature from URL
        extracted_jwt = params["request"][0]
        decoded = pyjwt.decode(
            extracted_jwt,
            pub_pem,
            algorithms=["ES256"],
            audience="https://auth.example.com",
        )
        assert decoded["client_id"] == "url-app"
        assert decoded["redirect_uri"] == "https://app.com/cb"

    def test_ps256_algorithm(self):
        """Verify PS256 (RSA-PSS) algorithm support."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        pub_pem = key.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        )

        request_jwt = create_request_object(
            private_key=pem,
            algorithm="PS256",
            client_id="ps256-app",
            audience="https://auth.example.com",
            redirect_uri="https://app.com/cb",
        )

        decoded = pyjwt.decode(
            request_jwt,
            pub_pem,
            algorithms=["PS256"],
            audience="https://auth.example.com",
        )
        assert decoded["iss"] == "ps256-app"
