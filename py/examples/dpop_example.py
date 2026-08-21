"""
DPoP (Demonstrating Proof of Possession) Example (RFC 9449)

Demonstrates token binding using DPoP proofs to prevent token theft.
"""

from py_identity_model import (
    build_dpop_headers,
    create_dpop_proof,
    generate_dpop_key,
)


def dpop_token_request():
    """Create DPoP proof for a token endpoint request."""
    print("\n" + "=" * 60)
    print("DPoP Token Request")
    print("=" * 60)

    # Step 1: Generate a DPoP key pair (do this once per session)
    key = generate_dpop_key("ES256")
    print(f"\n  Algorithm: {key.algorithm}")
    print(f"  JWK Thumbprint: {key.jwk_thumbprint[:30]}...")

    # Step 2: Create DPoP proof for token endpoint
    proof = create_dpop_proof(key, "POST", "https://auth.example.com/token")
    print(f"  Proof JWT: {proof[:50]}...")

    # Step 3: Add to request headers
    headers = build_dpop_headers(proof)
    print(f"  Headers: {list(headers.keys())}")
    print("  (Send these headers with your token request)")


def dpop_resource_request():
    """Create DPoP proof for a resource server request."""
    print("\n" + "=" * 60)
    print("DPoP Resource Server Request")
    print("=" * 60)

    key = generate_dpop_key()
    access_token = "bound_access_token_here"

    # Create proof with access token hash (ath claim)
    proof = create_dpop_proof(
        key,
        "GET",
        "https://api.example.com/resource",
        access_token=access_token,
    )

    # Headers include both DPoP proof and Authorization
    headers = build_dpop_headers(proof, access_token)
    print(f"\n  DPoP header: {proof[:40]}...")
    print(f"  Authorization: {headers['Authorization'][:30]}...")


def main():
    print("\n" + "=" * 60)
    print("DPoP EXAMPLES (RFC 9449)")
    print("=" * 60)

    dpop_token_request()
    dpop_resource_request()

    print("\n" + "=" * 60)
    print("Examples completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
