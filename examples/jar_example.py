"""
JWT Secured Authorization Request (JAR) Example (RFC 9101)

Demonstrates creating signed request objects and building
authorization URLs with the `request` parameter.
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from py_identity_model import (
    build_jar_authorization_url,
    create_request_object,
    generate_pkce_pair,
)


def jar_basic_example():
    """Create a signed request object and build authorization URL."""
    print("\n" + "=" * 60)
    print("JAR - Basic Request Object")
    print("=" * 60)

    # Generate an EC key pair for signing
    key = ec.generate_private_key(ec.SECP256R1())
    private_pem = key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    )

    # Create a signed request object
    request_jwt = create_request_object(
        private_key=private_pem,
        algorithm="ES256",
        client_id="my-app",
        audience="https://auth.example.com",
        redirect_uri="https://myapp.com/callback",
        scope="openid profile email",
        state="random-csrf-state",
        nonce="random-nonce",
    )

    print(f"\n  Request object (first 80 chars): {request_jwt[:80]}...")
    print(f"  JWT length: {len(request_jwt)} bytes")

    # Build authorization URL with the request parameter
    url = build_jar_authorization_url(
        authorization_endpoint="https://auth.example.com/authorize",
        client_id="my-app",
        request_object=request_jwt,
        scope="openid profile email",
        response_type="code",
    )

    print(f"\n  Authorization URL (first 120 chars):\n  {url[:120]}...")


def jar_with_pkce_example():
    """Combine JAR with PKCE for maximum security."""
    print("\n" + "=" * 60)
    print("JAR - Combined with PKCE")
    print("=" * 60)

    key = ec.generate_private_key(ec.SECP256R1())
    private_pem = key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    )

    # Generate PKCE pair
    verifier, challenge = generate_pkce_pair()

    # Include PKCE challenge in the signed request object
    request_jwt = create_request_object(
        private_key=private_pem,
        algorithm="ES256",
        client_id="secure-app",
        audience="https://auth.example.com",
        redirect_uri="https://myapp.com/callback",
        code_challenge=challenge,
        code_challenge_method="S256",
    )

    print(f"\n  Code verifier (store securely): {verifier[:30]}...")
    print(f"  Code challenge (in JWT): {challenge[:30]}...")
    print(f"  Request object created: {len(request_jwt)} bytes")
    print("  (Use verifier when exchanging the authorization code)")


def main():
    jar_basic_example()
    jar_with_pkce_example()
    print("\n" + "=" * 60)
    print("Examples completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
