"""
OAuth 2.0 Token Introspection Example (RFC 7662)

Demonstrates how to introspect tokens to check their validity and metadata.
"""

from py_identity_model import (
    TokenIntrospectionRequest,
)


def introspect_access_token():
    """Introspect an access token to check if it's still valid."""
    print("\n" + "=" * 60)
    print("Token Introspection Example")
    print("=" * 60)

    # Build the request
    request = TokenIntrospectionRequest(
        address="https://auth.example.com/introspect",
        token="eyJhbGciOi...",  # The token to check
        client_id="my-backend-app",
        client_secret="my-secret",
        token_type_hint="access_token",
    )

    print(f"\n  Endpoint: {request.address}")
    print(f"  Token type hint: {request.token_type_hint}")
    print("  (Would call introspect_token() with real credentials)")

    # Simulated response handling
    print("\n  Typical response handling:")
    print("    if response.is_successful:")
    print("      if response.claims['active']:")
    print("        print(f'Token valid, scope: {response.claims[\"scope\"]}')")
    print("      else:")
    print("        print('Token is inactive/expired')")


def main():
    print("\n" + "=" * 60)
    print("TOKEN INTROSPECTION EXAMPLES")
    print("=" * 60)

    introspect_access_token()

    print("\n" + "=" * 60)
    print("Examples completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
