"""
FAPI 2.0 Security Profile — Relying Party flow (DPoP path)

Demonstrates a FAPI 2.0 confidential-client authorization flow assembled from
py-identity-model's public API:

  1. PAR (RFC 9126) with ``private_key_jwt`` client auth (RFC 7523), PKCE ``S256``,
     and a DPoP-bound (RFC 9449) pushed authorization request.
  2. Front-channel authorization request carrying only ``client_id`` +
     ``request_uri``.
  3. DPoP-bound authorization-code token exchange with ``private_key_jwt``.
  4. RFC 9207 ``iss`` authorization-response validation (mix-up defense).
  5. DPoP-bound UserInfo (sender-constrained resource access).

This example is offline/dry — it builds the request objects and exercises the
local crypto (key generation, PKCE, DPoP proofs) without contacting a live
authorization server. In a real RP you would call ``push_authorization_request``,
``request_authorization_code_token`` and ``get_userinfo`` with these requests.
"""

from urllib.parse import urlencode

from py_identity_model import (
    AuthorizationCodeTokenRequest,
    PrivateKeyJwt,
    PushedAuthorizationRequest,
    UserInfoRequest,
    generate_dpop_key,
    generate_pkce_pair,
    parse_authorize_callback_response,
    validate_authorize_callback_issuer,
)


ISSUER = "https://as.example.com"
PAR_ENDPOINT = f"{ISSUER}/par"
TOKEN_ENDPOINT = f"{ISSUER}/token"
USERINFO_ENDPOINT = f"{ISSUER}/userinfo"
CLIENT_ID = "fapi2-rp"
REDIRECT_URI = "https://rp.example.com/callback"


def fapi2_rp_flow() -> None:
    print("\n" + "=" * 60)
    print("FAPI 2.0 RP flow (DPoP path)")
    print("=" * 60)

    # The RP holds a long-lived ES256 signing key for private_key_jwt assertions
    # (registered with the AS as the client's JWKS). FAPI 2.0 allows PS256/ES256.
    client_auth_key = generate_dpop_key("ES256")
    private_key_jwt = PrivateKeyJwt(
        private_key=client_auth_key.private_key_pem,
        algorithm="ES256",
        kid="fapi2-rp-key-1",
    )

    # A fresh DPoP key binds this flow's tokens to the client (RFC 9449).
    dpop_key = generate_dpop_key("ES256")

    # PKCE S256 is mandatory in FAPI 2.0.
    code_verifier, code_challenge = generate_pkce_pair()
    state = "opaque-csrf-state"
    nonce = "opaque-nonce"

    # Step 1: Pushed Authorization Request (private_key_jwt + DPoP + PKCE S256).
    par_request = PushedAuthorizationRequest(
        address=PAR_ENDPOINT,
        client_id=CLIENT_ID,
        redirect_uri=REDIRECT_URI,
        scope="openid profile",
        state=state,
        nonce=nonce,
        code_challenge=code_challenge,
        code_challenge_method="S256",
        private_key_jwt=private_key_jwt,
        dpop_key=dpop_key,
    )
    print(f"\n  1. PAR -> {par_request.address}")
    print("     client auth: private_key_jwt (ES256)")
    print("     sender-constrained: DPoP; PKCE: S256")
    print("     (push_authorization_request returns a request_uri)")

    # Step 2: front channel carries ONLY client_id + request_uri (RFC 9126 §4).
    print("\n  2. Authorize ->")
    print(f"     {ISSUER}/authorize?client_id={CLIENT_ID}&request_uri=urn:...")

    # Step 3: DPoP-bound token exchange with private_key_jwt.
    token_request = AuthorizationCodeTokenRequest(
        address=TOKEN_ENDPOINT,
        client_id=CLIENT_ID,
        code="authorization-code-from-callback",
        redirect_uri=REDIRECT_URI,
        code_verifier=code_verifier,
        private_key_jwt=private_key_jwt,
        dpop_key=dpop_key,
    )
    print(f"\n  3. Token exchange -> {token_request.address}")
    print("     DPoP-bound + private_key_jwt (token proof has no ath)")

    # Step 4: RFC 9207 iss validation on the authorization response. The AS
    # returns ``iss`` as a front-channel parameter; parse it, then validate.
    callback_query = urlencode(
        {"code": "authorization-code-from-callback", "state": state, "iss": ISSUER}
    )
    callback = parse_authorize_callback_response(f"{REDIRECT_URI}?{callback_query}")
    iss_result = validate_authorize_callback_issuer(callback, ISSUER, require=True)
    print("\n  4. RFC 9207 iss validation:", "OK" if iss_result.is_valid else "FAIL")

    # Step 5: DPoP-bound UserInfo (the resource proof DOES carry ath).
    userinfo_request = UserInfoRequest(
        address=USERINFO_ENDPOINT,
        token="dpop-bound-access-token",
        dpop_key=dpop_key,
    )
    print(f"\n  5. UserInfo -> {userinfo_request.address}")
    print("     Authorization: DPoP <token> + resource proof (ath present)")


def main() -> None:
    fapi2_rp_flow()
    print("\n" + "=" * 60)
    print("Example completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
