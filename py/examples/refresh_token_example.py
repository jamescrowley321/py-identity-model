"""
OAuth 2.0 Refresh Token Grant Example (RFC 6749 Section 6)

Demonstrates how to refresh an access token using a refresh token.
"""

from py_identity_model import RefreshTokenRequest


def refresh_access_token():
    """Refresh an expired access token."""
    print("\n" + "=" * 60)
    print("Refresh Token Example")
    print("=" * 60)

    request = RefreshTokenRequest(
        address="https://auth.example.com/token",
        client_id="my-app",
        refresh_token="stored_refresh_token",
        client_secret="my-secret",
        scope="openid profile",
    )

    print(f"\n  Token endpoint: {request.address}")
    print(f"  Scope: {request.scope}")
    print("  (Would call refresh_token() with real credentials)")
    print("  On success: response.token['access_token'] = new token")


def main():
    refresh_access_token()
    print("\n" + "=" * 60)
    print("Examples completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
