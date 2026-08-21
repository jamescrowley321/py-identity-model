"""
Pushed Authorization Requests (PAR) Example (RFC 9126)

Demonstrates pushing authorization parameters to the PAR endpoint.
"""

from py_identity_model import PushedAuthorizationRequest


def par_example():
    """Push authorization parameters to get a request_uri."""
    print("\n" + "=" * 60)
    print("Pushed Authorization Request (PAR)")
    print("=" * 60)

    request = PushedAuthorizationRequest(
        address="https://auth.example.com/par",
        client_id="my-app",
        redirect_uri="https://myapp.com/callback",
        scope="openid profile",
        state="csrf_token",
        code_challenge="pkce_challenge",
        code_challenge_method="S256",
        client_secret="my-secret",
    )

    print(f"\n  PAR endpoint: {request.address}")
    print(f"  Scope: {request.scope}")
    print("  (Would call push_authorization_request())")
    print("  On success: use response.request_uri in authorization URL")


def main():
    par_example()
    print("\n" + "=" * 60)
    print("Examples completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
