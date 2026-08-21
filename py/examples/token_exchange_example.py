"""
Token Exchange Example (RFC 8693)

Demonstrates OAuth 2.0 Token Exchange for delegation and
impersonation scenarios in microservice architectures.
"""

from py_identity_model import TokenExchangeRequest
from py_identity_model.core.token_type import ACCESS_TOKEN, JWT


def impersonation_example():
    """Exchange a user's token for a new token at a downstream service."""
    print("\n" + "=" * 60)
    print("Token Exchange - Impersonation")
    print("=" * 60)

    request = TokenExchangeRequest(
        address="https://auth.example.com/token",
        client_id="backend-service",
        subject_token="eyJhbGciOiJSUzI1NiJ9...",
        subject_token_type=ACCESS_TOKEN,
        audience="downstream-api",
        scope="read write",
        client_secret="service-secret",
    )

    print(f"\n  Token endpoint: {request.address}")
    print(f"  Subject token type: {request.subject_token_type}")
    print(f"  Audience: {request.audience}")
    print("  (Would call exchange_token())")
    print("  Result: new access token scoped to downstream-api")


def delegation_example():
    """Exchange tokens with an actor token for delegation."""
    print("\n" + "=" * 60)
    print("Token Exchange - Delegation")
    print("=" * 60)

    request = TokenExchangeRequest(
        address="https://auth.example.com/token",
        client_id="service-a",
        subject_token="user-access-token",
        subject_token_type=ACCESS_TOKEN,
        actor_token="service-a-jwt",
        actor_token_type=JWT,
        audience="service-b",
        client_secret="service-a-secret",
    )

    print(f"\n  Token endpoint: {request.address}")
    print(f"  Subject (user): token type = {request.subject_token_type}")
    print(f"  Actor (service): token type = {request.actor_token_type}")
    print(f"  Target audience: {request.audience}")
    print("  (Would call exchange_token())")
    print("  Result: token for service-b acting on behalf of user")


def main():
    impersonation_example()
    delegation_example()
    print("\n" + "=" * 60)
    print("Examples completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
