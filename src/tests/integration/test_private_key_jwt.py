"""Integration tests for ``private_key_jwt`` client authentication.

Exercises RFC 7523 / OpenID Connect Core 1.0 Section 9 client authentication
against a live OIDC provider.  The library signs a ``client_assertion`` with
the client's private key; the provider verifies it against the public JWK
registered for the client.

These tests are specific to the bundled node-oidc-provider fixture, which
registers a ``test-private-key-jwt`` client whose public key matches the
static private key embedded below.  They are skipped against any other
provider (remote providers in the CI matrix do not register this client).
"""

import secrets

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
import pytest

from py_identity_model import (
    ClientCredentialsTokenRequest,
    PrivateKeyJwt,
    PushedAuthorizationRequest,
    generate_pkce_pair,
    push_authorization_request,
    request_client_credentials_token,
)

from .conftest import AuthCodeFlowConfig, perform_auth_code_flow


# Client registered in the node-oidc-provider fixture (provider.js).
PKJWT_CLIENT_ID = "test-private-key-jwt"
PKJWT_REDIRECT_URI = "http://localhost:8080/callback"
PKJWT_ALGORITHM = "ES256"
PKJWT_KID = "pkjwt-client-key"

# Static ES256 (P-256) private key. The matching public JWK is registered
# for ``test-private-key-jwt`` in the node-oidc-provider fixture. Test-only
# key — never use a checked-in key outside of a disposable test fixture.
PKJWT_PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg8WGr0RG4Zo7/WD6g
uOCH355J2/auzrggNZRPhCSxQfGhRANCAATbM7xgqsqkG4DJUQPYKHBlgV/OS3nZ
E2+SampTwVolT/BEG7coOzdYem3Yr2FkBicTXhqWNGiG7RWkD+d/rVhW
-----END PRIVATE KEY-----
"""


def _is_node_oidc_fixture(raw_discovery: dict) -> bool:
    """Whether the active provider is the local private_key_jwt fixture.

    The static key only matches the ``test-private-key-jwt`` client in the
    bundled node-oidc-provider fixture, which runs on localhost and
    advertises ``private_key_jwt`` support.
    """
    issuer = raw_discovery.get("issuer", "")
    methods = raw_discovery.get("token_endpoint_auth_methods_supported", [])
    return issuer.startswith(("http://localhost", "http://127.0.0.1")) and (
        "private_key_jwt" in methods
    )


def _require_node_oidc(raw_discovery: dict) -> None:
    if not _is_node_oidc_fixture(raw_discovery):
        pytest.skip(
            "private_key_jwt fixture client only registered in node-oidc-provider"
        )


def _private_key_jwt(audience: str | None = None) -> PrivateKeyJwt:
    return PrivateKeyJwt(
        private_key=PKJWT_PRIVATE_KEY,
        algorithm=PKJWT_ALGORITHM,
        kid=PKJWT_KID,
        audience=audience,
    )


@pytest.mark.integration
class TestPrivateKeyJwtLive:
    """private_key_jwt client authentication against a live provider."""

    def test_client_credentials_with_private_key_jwt(
        self,
        raw_discovery,
        token_endpoint,
    ):
        """Token endpoint authenticates the client via a signed assertion.

        No ``client_secret`` is supplied — the provider must accept solely on
        the strength of the verified ``client_assertion``.
        """
        _require_node_oidc(raw_discovery)

        response = request_client_credentials_token(
            ClientCredentialsTokenRequest(
                address=token_endpoint,
                client_id=PKJWT_CLIENT_ID,
                scope="api",
                private_key_jwt=_private_key_jwt(),
            )
        )

        assert response.is_successful is True, (
            f"private_key_jwt client_credentials failed: {response.error}"
        )
        assert response.token is not None
        assert response.token.get("access_token")
        assert response.token.get("token_type", "").lower() == "bearer"

    def test_client_credentials_wrong_key_rejected(
        self,
        raw_discovery,
        token_endpoint,
    ):
        """A mismatched signing key is rejected — proves real verification.

        A freshly generated key does not match the client's registered public
        JWK, so the assertion signature must fail verification at the provider.
        """
        _require_node_oidc(raw_discovery)

        wrong_key = ec.generate_private_key(ec.SECP256R1()).private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )

        response = request_client_credentials_token(
            ClientCredentialsTokenRequest(
                address=token_endpoint,
                client_id=PKJWT_CLIENT_ID,
                scope="api",
                private_key_jwt=PrivateKeyJwt(
                    private_key=wrong_key,
                    algorithm=PKJWT_ALGORITHM,
                    kid=PKJWT_KID,
                ),
            )
        )

        assert response.is_successful is False
        assert response.error is not None

    def test_par_with_private_key_jwt(
        self,
        provider_capabilities,
        raw_discovery,
    ):
        """PAR endpoint authenticates the client via a signed assertion."""
        _require_node_oidc(raw_discovery)
        if "par" not in provider_capabilities:
            pytest.skip("Provider does not support PAR")

        endpoint = raw_discovery["pushed_authorization_request_endpoint"]
        _verifier, challenge = generate_pkce_pair()

        response = push_authorization_request(
            PushedAuthorizationRequest(
                address=endpoint,
                client_id=PKJWT_CLIENT_ID,
                redirect_uri=PKJWT_REDIRECT_URI,
                scope="openid",
                code_challenge=challenge,
                code_challenge_method="S256",
                state=secrets.token_urlsafe(32),
                private_key_jwt=_private_key_jwt(),
            )
        )

        assert response.is_successful is True, f"PAR failed: {response.error}"
        assert response.request_uri is not None
        assert response.request_uri.startswith("urn:ietf:params:oauth:request_uri:")
        assert response.expires_in is not None
        assert response.expires_in > 0

    def test_authorization_code_with_private_key_jwt(
        self,
        provider_capabilities,
        raw_discovery,
        discovery_document,
    ):
        """Full auth-code flow exchanges the code with a signed assertion.

        Drives the devInteractions login/consent to obtain a code, then
        authenticates the token request with ``private_key_jwt`` (no secret).
        """
        _require_node_oidc(raw_discovery)
        if "dev_interactions" not in provider_capabilities:
            pytest.skip("Provider does not support automated auth code flow")

        result = perform_auth_code_flow(
            discovery=discovery_document,
            client_id=PKJWT_CLIENT_ID,
            redirect_uri=PKJWT_REDIRECT_URI,
            config=AuthCodeFlowConfig(
                scope="openid profile email offline_access",
                resource="urn:test:api",
                private_key_jwt=_private_key_jwt(),
            ),
        )

        token_response = result["token_response"]
        assert token_response.is_successful is True, (
            f"auth-code private_key_jwt token exchange failed: {token_response.error}"
        )
        assert token_response.token is not None
        assert token_response.token.get("access_token")
