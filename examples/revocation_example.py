"""
OAuth 2.0 Token Revocation Example (RFC 7009)

Demonstrates how to revoke access and refresh tokens.
"""

from py_identity_model import TokenRevocationRequest


def revoke_access_token():
    """Revoke an access token on user logout."""
    print("\n" + "=" * 60)
    print("Token Revocation Example")
    print("=" * 60)

    request = TokenRevocationRequest(
        address="https://auth.example.com/revoke",
        token="eyJhbGciOi...",
        client_id="my-app",
        client_secret="my-secret",
        token_type_hint="access_token",
    )

    print(f"\n  Endpoint: {request.address}")
    print(f"  Token type hint: {request.token_type_hint}")
    print("  (Would call revoke_token() with real credentials)")
    print("  On success: response.is_successful == True")


def main():
    revoke_access_token()
    print("\n" + "=" * 60)
    print("Examples completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
