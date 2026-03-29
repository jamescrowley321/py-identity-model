"""Unit tests for JWT Secured Authorization Request (JAR, RFC 9101)."""

from urllib.parse import parse_qs, urlparse

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
import jwt as pyjwt
import pytest

from py_identity_model.core.jar import (
    build_jar_authorization_url,
    create_request_object,
)


def _ec_private_key_pem() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def _rsa_private_key_pem() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


AUTH_ENDPOINT = "https://auth.example.com/authorize"


@pytest.mark.unit
class TestCreateRequestObject:
    def test_basic_ec256(self):
        pem = _ec_private_key_pem()
        token = create_request_object(
            private_key=pem,
            algorithm="ES256",
            client_id="my-app",
            audience="https://auth.example.com",
            redirect_uri="https://app.com/cb",
        )
        decoded = pyjwt.decode(token, options={"verify_signature": False})
        assert decoded["iss"] == "my-app"
        assert decoded["aud"] == "https://auth.example.com"
        assert decoded["client_id"] == "my-app"
        assert decoded["redirect_uri"] == "https://app.com/cb"
        assert decoded["scope"] == "openid"
        assert decoded["response_type"] == "code"
        assert "iat" in decoded
        assert "nbf" in decoded
        assert "exp" in decoded

    def test_basic_rsa256(self):
        pem = _rsa_private_key_pem()
        token = create_request_object(
            private_key=pem,
            algorithm="RS256",
            client_id="rsa-app",
            audience="https://auth.example.com",
            redirect_uri="https://app.com/cb",
        )
        header = pyjwt.get_unverified_header(token)
        assert header["alg"] == "RS256"
        decoded = pyjwt.decode(token, options={"verify_signature": False})
        assert decoded["iss"] == "rsa-app"

    def test_with_pkce(self):
        pem = _ec_private_key_pem()
        token = create_request_object(
            private_key=pem,
            algorithm="ES256",
            client_id="app",
            audience="https://auth.example.com",
            redirect_uri="https://app.com/cb",
            code_challenge="abc123",
            code_challenge_method="S256",
        )
        decoded = pyjwt.decode(token, options={"verify_signature": False})
        assert decoded["code_challenge"] == "abc123"
        assert decoded["code_challenge_method"] == "S256"

    def test_with_state_and_nonce(self):
        pem = _ec_private_key_pem()
        token = create_request_object(
            private_key=pem,
            algorithm="ES256",
            client_id="app",
            audience="https://auth.example.com",
            redirect_uri="https://app.com/cb",
            state="csrf-value",
            nonce="nonce-value",
        )
        decoded = pyjwt.decode(token, options={"verify_signature": False})
        assert decoded["state"] == "csrf-value"
        assert decoded["nonce"] == "nonce-value"

    def test_extra_claims(self):
        pem = _ec_private_key_pem()
        token = create_request_object(
            private_key=pem,
            algorithm="ES256",
            client_id="app",
            audience="https://auth.example.com",
            redirect_uri="https://app.com/cb",
            acr_values="urn:mace:incommon:iap:silver",
        )
        decoded = pyjwt.decode(token, options={"verify_signature": False})
        assert decoded["acr_values"] == "urn:mace:incommon:iap:silver"

    def test_custom_scope_and_response_type(self):
        pem = _ec_private_key_pem()
        token = create_request_object(
            private_key=pem,
            algorithm="ES256",
            client_id="app",
            audience="https://auth.example.com",
            redirect_uri="https://app.com/cb",
            scope="openid profile email",
            response_type="code id_token",
        )
        decoded = pyjwt.decode(token, options={"verify_signature": False})
        assert decoded["scope"] == "openid profile email"
        assert decoded["response_type"] == "code id_token"

    def test_lifetime(self):
        pem = _ec_private_key_pem()
        token = create_request_object(
            private_key=pem,
            algorithm="ES256",
            client_id="app",
            audience="https://auth.example.com",
            redirect_uri="https://app.com/cb",
            lifetime=600,
        )
        decoded = pyjwt.decode(token, options={"verify_signature": False})
        assert decoded["exp"] - decoded["iat"] == 600

    def test_unsupported_algorithm(self):
        pem = _ec_private_key_pem()
        with pytest.raises(ValueError, match="Unsupported JAR algorithm"):
            create_request_object(
                private_key=pem,
                algorithm="HS256",
                client_id="app",
                audience="https://auth.example.com",
                redirect_uri="https://app.com/cb",
            )

    def test_reserved_claim_rejected(self):
        pem = _ec_private_key_pem()
        with pytest.raises(ValueError, match="reserved claims"):
            create_request_object(
                private_key=pem,
                algorithm="ES256",
                client_id="app",
                audience="https://auth.example.com",
                redirect_uri="https://app.com/cb",
                iss="evil-issuer",
            )

    def test_reserved_claim_exp_rejected(self):
        pem = _ec_private_key_pem()
        with pytest.raises(ValueError, match="reserved claims"):
            create_request_object(
                private_key=pem,
                algorithm="ES256",
                client_id="app",
                audience="https://auth.example.com",
                redirect_uri="https://app.com/cb",
                exp="99999999999",
            )

    def test_reserved_claims_includes_oauth_params(self):
        """M1: _RESERVED_CLAIMS guards state/nonce/code_challenge/code_challenge_method.

        These are explicit keyword args so Python routing prevents them from
        entering extra_claims in normal usage. The frozenset is defense-in-depth
        against programmatic dict construction.
        """
        from py_identity_model.core.jar import _RESERVED_CLAIMS

        for claim in (
            "state",
            "nonce",
            "code_challenge",
            "code_challenge_method",
            "jti",
        ):
            assert claim in _RESERVED_CLAIMS, (
                f"{claim} missing from _RESERVED_CLAIMS"
            )

    def test_kid_included_in_header(self):
        """M2: kid parameter appears in JWT header for key lookup."""
        pem = _ec_private_key_pem()
        token = create_request_object(
            private_key=pem,
            algorithm="ES256",
            client_id="app",
            audience="https://auth.example.com",
            redirect_uri="https://app.com/cb",
            kid="my-key-id-123",
        )
        header = pyjwt.get_unverified_header(token)
        assert header["kid"] == "my-key-id-123"

    def test_kid_absent_when_not_provided(self):
        """M2: kid is not in header when omitted."""
        pem = _ec_private_key_pem()
        token = create_request_object(
            private_key=pem,
            algorithm="ES256",
            client_id="app",
            audience="https://auth.example.com",
            redirect_uri="https://app.com/cb",
        )
        header = pyjwt.get_unverified_header(token)
        assert "kid" not in header

    def test_jti_claim_present(self):
        """S2: jti claim included by default for replay protection."""
        pem = _ec_private_key_pem()
        token = create_request_object(
            private_key=pem,
            algorithm="ES256",
            client_id="app",
            audience="https://auth.example.com",
            redirect_uri="https://app.com/cb",
        )
        decoded = pyjwt.decode(token, options={"verify_signature": False})
        assert "jti" in decoded
        assert len(decoded["jti"]) == 36  # UUID format

    def test_jti_unique_per_call(self):
        """S2: each request object gets a unique jti."""
        pem = _ec_private_key_pem()
        kwargs = {
            "private_key": pem,
            "algorithm": "ES256",
            "client_id": "app",
            "audience": "https://auth.example.com",
            "redirect_uri": "https://app.com/cb",
        }
        t1 = pyjwt.decode(
            create_request_object(**kwargs),
            options={"verify_signature": False},
        )
        t2 = pyjwt.decode(
            create_request_object(**kwargs),
            options={"verify_signature": False},
        )
        assert t1["jti"] != t2["jti"]

    def test_pkce_requires_both_challenge_and_method(self):
        """S3: code_challenge without code_challenge_method raises ValueError."""
        pem = _ec_private_key_pem()
        with pytest.raises(ValueError, match="code_challenge.*both"):
            create_request_object(
                private_key=pem,
                algorithm="ES256",
                client_id="app",
                audience="https://auth.example.com",
                redirect_uri="https://app.com/cb",
                code_challenge="abc",
            )

    def test_pkce_requires_both_method_and_challenge(self):
        """S3: code_challenge_method without code_challenge raises ValueError."""
        pem = _ec_private_key_pem()
        with pytest.raises(ValueError, match="code_challenge.*both"):
            create_request_object(
                private_key=pem,
                algorithm="ES256",
                client_id="app",
                audience="https://auth.example.com",
                redirect_uri="https://app.com/cb",
                code_challenge_method="S256",
            )

    def test_zero_lifetime_rejected(self):
        pem = _ec_private_key_pem()
        with pytest.raises(ValueError, match="lifetime must be positive"):
            create_request_object(
                private_key=pem,
                algorithm="ES256",
                client_id="app",
                audience="https://auth.example.com",
                redirect_uri="https://app.com/cb",
                lifetime=0,
            )

    def test_negative_lifetime_rejected(self):
        pem = _ec_private_key_pem()
        with pytest.raises(ValueError, match="lifetime must be positive"):
            create_request_object(
                private_key=pem,
                algorithm="ES256",
                client_id="app",
                audience="https://auth.example.com",
                redirect_uri="https://app.com/cb",
                lifetime=-10,
            )

    def test_optional_params_omitted_when_none(self):
        pem = _ec_private_key_pem()
        token = create_request_object(
            private_key=pem,
            algorithm="ES256",
            client_id="app",
            audience="https://auth.example.com",
            redirect_uri="https://app.com/cb",
        )
        decoded = pyjwt.decode(token, options={"verify_signature": False})
        assert "state" not in decoded
        assert "nonce" not in decoded
        assert "code_challenge" not in decoded
        assert "code_challenge_method" not in decoded

    def test_jwt_header(self):
        pem = _ec_private_key_pem()
        token = create_request_object(
            private_key=pem,
            algorithm="ES256",
            client_id="app",
            audience="https://auth.example.com",
            redirect_uri="https://app.com/cb",
        )
        header = pyjwt.get_unverified_header(token)
        assert header["alg"] == "ES256"
        assert header["typ"] == "JWT"


@pytest.mark.unit
class TestBuildJARAuthorizationUrl:
    def test_basic_url(self):
        url = build_jar_authorization_url(
            authorization_endpoint=AUTH_ENDPOINT,
            client_id="my-app",
            request_object="eyJ...",
        )
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        assert params["client_id"] == ["my-app"]
        assert params["request"] == ["eyJ..."]
        assert "scope" not in params
        assert "response_type" not in params

    def test_with_duplicated_params(self):
        url = build_jar_authorization_url(
            authorization_endpoint=AUTH_ENDPOINT,
            client_id="my-app",
            request_object="eyJ...",
            scope="openid",
            response_type="code",
        )
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        assert params["client_id"] == ["my-app"]
        assert params["request"] == ["eyJ..."]
        assert params["scope"] == ["openid"]
        assert params["response_type"] == ["code"]

    def test_endpoint_with_existing_query(self):
        url = build_jar_authorization_url(
            authorization_endpoint=AUTH_ENDPOINT + "?foo=bar",
            client_id="my-app",
            request_object="eyJ...",
        )
        assert "?foo=bar&client_id=" in url

    def test_url_starts_with_endpoint(self):
        url = build_jar_authorization_url(
            authorization_endpoint=AUTH_ENDPOINT,
            client_id="app",
            request_object="jwt",
        )
        assert url.startswith(AUTH_ENDPOINT + "?")
