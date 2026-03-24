"""
Authorization Code Grant with PKCE Example for py-identity-model

Demonstrates the complete OAuth 2.0 Authorization Code flow with PKCE:
1. Generate PKCE code verifier and challenge
2. Build authorization URL
3. Parse callback response
4. Exchange authorization code for tokens
"""

import secrets

from py_identity_model import (
    AuthorizationCodeTokenRequest,
    build_authorization_url,
    generate_pkce_pair,
    parse_authorize_callback_response,
    validate_authorize_callback_state,
)


def auth_code_pkce_flow():
    """Demonstrate the complete authorization code flow with PKCE."""
    print("\n" + "=" * 60)
    print("Authorization Code Grant with PKCE")
    print("=" * 60)

    # Step 1: Generate PKCE pair
    code_verifier, code_challenge = generate_pkce_pair()
    state = secrets.token_urlsafe(32)

    print(f"\n  Code Verifier: {code_verifier[:30]}...")
    print(f"  Code Challenge: {code_challenge}")
    print(f"  State: {state[:20]}...")

    # Step 2: Build authorization URL
    authorize_url = build_authorization_url(
        authorization_endpoint="https://auth.example.com/authorize",
        client_id="my-spa-app",
        redirect_uri="https://myapp.com/callback",
        scope="openid profile email",
        state=state,
        code_challenge=code_challenge,
        code_challenge_method="S256",
    )
    print(f"\n  Authorize URL: {authorize_url[:80]}...")
    print("  (Redirect user to this URL)")

    # Step 3: Parse callback (simulated)
    simulated_callback = (
        f"https://myapp.com/callback?code=auth_code_abc123&state={state}"
    )
    callback_response = parse_authorize_callback_response(simulated_callback)

    if not callback_response.is_successful:
        print(f"  Error: {callback_response.error}")
        return

    # Step 4: Validate state (CSRF protection)
    validation = validate_authorize_callback_state(callback_response, state)
    if not validation.is_valid:
        print(f"  State validation failed: {validation.error}")
        return

    code = callback_response.code
    print(f"\n  Authorization code: {code}")
    print("  State validation: passed")

    if code is None:
        print("  Error: no authorization code in callback")
        return

    # Step 5: Build token exchange request
    token_request = AuthorizationCodeTokenRequest(
        address="https://auth.example.com/token",
        client_id="my-spa-app",
        code=code,
        redirect_uri="https://myapp.com/callback",
        code_verifier=code_verifier,  # PKCE proof
    )

    print(f"\n  Token endpoint: {token_request.address}")
    print(
        f"  Code verifier included: {token_request.code_verifier is not None}"
    )
    print("  (Would call request_authorization_code_token() here)")


def confidential_client_example():
    """Show auth code flow for confidential clients (with client_secret)."""
    print("\n" + "=" * 60)
    print("Confidential Client (with client_secret)")
    print("=" * 60)

    token_request = AuthorizationCodeTokenRequest(
        address="https://auth.example.com/token",
        client_id="my-backend-app",
        code="auth_code_xyz",
        redirect_uri="https://backend.example.com/callback",
        client_secret="super_secret",  # Confidential client
        scope="openid offline_access",
    )

    print(f"\n  Client ID: {token_request.client_id}")
    print(f"  Has client_secret: {token_request.client_secret is not None}")
    print(f"  Scope: {token_request.scope}")


def main():
    print("\n" + "=" * 60)
    print("AUTH CODE + PKCE EXAMPLES")
    print("=" * 60)

    auth_code_pkce_flow()
    confidential_client_example()

    print("\n" + "=" * 60)
    print("All auth code examples completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
