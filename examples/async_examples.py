"""
Async Examples for py-identity-model

This module demonstrates how to use the async API for non-blocking I/O operations.
Perfect for async web frameworks like FastAPI, Starlette, or async applications.
"""

import asyncio

from py_identity_model import DiscoveryDocumentRequest, TokenValidationConfig
from py_identity_model.aio import (
    ClientCredentialsTokenRequest,
    JwksRequest,
    get_discovery_document,
    get_jwks,
    request_client_credentials_token,
    validate_token,
)


# Constants
DEMO_DISCOVERY_URL = (
    "https://demo.duendesoftware.com/.well-known/openid-configuration"
)


# =============================================================================
# Example 1: Async Discovery Document Fetching
# =============================================================================


async def fetch_discovery_document_example():
    """Fetch discovery document asynchronously."""
    print("\\n" + "=" * 60)
    print("Example 1: Async Discovery Document")
    print("=" * 60)

    discovery_request = DiscoveryDocumentRequest(address=DEMO_DISCOVERY_URL)

    # Async fetch - non-blocking
    response = await get_discovery_document(discovery_request)

    if response.is_successful:
        print("✓ Discovery successful!")
        print(f"  Issuer: {response.issuer}")
        print(f"  JWKS URI: {response.jwks_uri}")
        print(f"  Token Endpoint: {response.token_endpoint}")
        print(
            f"  Supported algorithms: {response.id_token_signing_alg_values_supported}"
        )
    else:
        print(f"✗ Discovery failed: {response.error}")

    return response


# =============================================================================
# Example 2: Async JWKS Fetching
# =============================================================================


async def fetch_jwks_example():
    """Fetch JWKS asynchronously."""
    print("\\n" + "=" * 60)
    print("Example 2: Async JWKS Fetching")
    print("=" * 60)

    jwks_request = JwksRequest(
        address="https://demo.duendesoftware.com/.well-known/openid-configuration/jwks"
    )

    # Async fetch - non-blocking
    response = await get_jwks(jwks_request)

    if response.is_successful:
        print("✓ JWKS fetched successfully!")
        print(f"  Number of keys: {len(response.keys)}")
        for key in response.keys:
            print(
                f"  - Key ID: {key.kid}, Algorithm: {key.alg}, Type: {key.kty}"
            )
    else:
        print(f"✗ JWKS fetch failed: {response.error}")

    return response


# =============================================================================
# Example 3: Async Client Credentials Token Request
# =============================================================================


async def request_token_example():
    """Request access token using client credentials flow asynchronously."""
    print("\\n" + "=" * 60)
    print("Example 3: Async Client Credentials Token")
    print("=" * 60)

    token_request = ClientCredentialsTokenRequest(
        address="https://demo.duendesoftware.com/connect/token",
        client_id="m2m",
        client_secret="secret",
        scope="api",
    )

    # Async request - non-blocking
    response = await request_client_credentials_token(token_request)

    if response.is_successful:
        print("✓ Token obtained successfully!")
        print(f"  Token Type: {response.token.get('token_type')}")
        print(f"  Expires In: {response.token.get('expires_in')} seconds")
        print(
            f"  Access Token (first 50 chars): {response.token.get('access_token')[:50]}..."
        )
        return response.token.get("access_token")
    print(f"✗ Token request failed: {response.error}")
    return None


# =============================================================================
# Example 4: Async Token Validation
# =============================================================================


async def validate_token_example(access_token: str):
    """Validate an access token asynchronously."""
    print("\\n" + "=" * 60)
    print("Example 4: Async Token Validation")
    print("=" * 60)

    try:
        # Configure token validation
        config = TokenValidationConfig(
            perform_disco=True,
            audience=None,  # Set to your API audience
            options={
                "verify_aud": False,  # Disabled for demo
                "require_aud": False,
            },
        )

        # Async validation - non-blocking
        decoded = await validate_token(
            access_token,
            config,
            disco_doc_address="https://demo.duendesoftware.com/.well-known/openid-configuration",
        )

        print("✓ Token validated successfully!")
        print(f"  Subject: {decoded.get('sub')}")
        print(f"  Issuer: {decoded.get('iss')}")
        print(f"  Client ID: {decoded.get('client_id')}")
        print(f"  Scope: {decoded.get('scope')}")
        return decoded

    except Exception as e:
        print(f"✗ Token validation failed: {e}")
        return None


# =============================================================================
# Example 5: Concurrent Operations (Power of Async!)
# =============================================================================


async def concurrent_operations_example():
    """Demonstrate concurrent async operations - the main benefit of async!"""
    print("\\n" + "=" * 60)
    print("Example 5: Concurrent Operations")
    print("=" * 60)
    print("Fetching discovery document and JWKS concurrently...")

    # Create tasks
    disco_task = get_discovery_document(
        DiscoveryDocumentRequest(
            address="https://demo.duendesoftware.com/.well-known/openid-configuration"
        )
    )

    jwks_task = get_jwks(
        JwksRequest(
            address="https://demo.duendesoftware.com/.well-known/openid-configuration/jwks"
        )
    )

    # Run concurrently - both requests happen at the same time!
    disco_response, jwks_response = await asyncio.gather(disco_task, jwks_task)

    print("\\n✓ Both operations completed concurrently!")
    print(f"  Discovery: {disco_response.is_successful}")
    print(
        f"  JWKS: {jwks_response.is_successful} ({len(jwks_response.keys)} keys)"
    )

    return disco_response, jwks_response


# =============================================================================
# Example 6: Multiple Token Validations Concurrently
# =============================================================================


async def validate_multiple_tokens_example(tokens: list[str]):
    """Validate multiple tokens concurrently."""
    print("\\n" + "=" * 60)
    print("Example 6: Concurrent Token Validations")
    print("=" * 60)
    print(f"Validating {len(tokens)} tokens concurrently...")

    config = TokenValidationConfig(
        perform_disco=True,
        audience=None,
        options={"verify_aud": False, "require_aud": False},
    )

    # Create validation tasks for all tokens
    tasks = [
        validate_token(
            token,
            config,
            disco_doc_address="https://demo.duendesoftware.com/.well-known/openid-configuration",
        )
        for token in tokens
    ]

    # Validate all tokens concurrently
    try:
        results = await asyncio.gather(*tasks, return_exceptions=True)

        successful = sum(1 for r in results if not isinstance(r, Exception))
        print(f"\\n✓ Validated {successful}/{len(tokens)} tokens successfully")
        return results
    except Exception as e:
        print(f"✗ Batch validation error: {e}")
        return []


# =============================================================================
# Example 7: FastAPI Integration Pattern
# =============================================================================


async def fastapi_pattern_example():
    """
    Example pattern for using async py-identity-model in FastAPI.

    This is a demonstration - in real FastAPI, you'd use dependency injection.
    """
    print("\\n" + "=" * 60)
    print("Example 7: FastAPI Integration Pattern")
    print("=" * 60)

    # Simulated FastAPI endpoint
    async def protected_endpoint(authorization: str):
        """Simulated FastAPI protected endpoint."""
        # Extract token from Authorization header
        if not authorization.startswith("Bearer "):
            return {"error": "Invalid authorization header"}

        token = authorization.replace("Bearer ", "")

        try:
            # Validate token asynchronously
            config = TokenValidationConfig(
                perform_disco=True,
                audience="api",
                options={"verify_aud": False},
            )

            claims = await validate_token(
                token,
                config,
                disco_doc_address="https://demo.duendesoftware.com/.well-known/openid-configuration",
            )

            return {
                "message": "Access granted",
                "user_id": claims.get("sub"),
                "scopes": claims.get("scope"),
            }
        except Exception as e:
            return {"error": f"Unauthorized: {e}"}

    # Get a token first
    token_request = ClientCredentialsTokenRequest(
        address="https://demo.duendesoftware.com/connect/token",
        client_id="m2m",
        client_secret="secret",
        scope="api",
    )

    token_response = await request_client_credentials_token(token_request)

    if token_response.is_successful:
        access_token = token_response.token.get("access_token")

        # Simulate the endpoint call
        result = await protected_endpoint(f"Bearer {access_token}")
        print(f"✓ Endpoint response: {result}")
        return result
    print("✗ Could not get token for demo")
    return None


# =============================================================================
# Main: Run All Examples
# =============================================================================


async def main():
    """Run all async examples."""
    print("\\n" + "=" * 60)
    print("PY-IDENTITY-MODEL ASYNC EXAMPLES")
    print("=" * 60)
    print(
        "\\nThese examples demonstrate async/await operations for non-blocking I/O."
    )
    print(
        "Perfect for async web frameworks (FastAPI, Starlette) and high-concurrency apps.\\n"
    )

    # Example 1: Discovery
    await fetch_discovery_document_example()

    # Example 2: JWKS
    await fetch_jwks_example()

    # Example 3: Token Request
    access_token = await request_token_example()

    # Example 4: Token Validation
    if access_token:
        await validate_token_example(access_token)

    # Example 5: Concurrent Operations (the power of async!)
    await concurrent_operations_example()

    # Example 6: Concurrent Token Validations
    if access_token:
        # For demo, validate the same token 3 times concurrently
        await validate_multiple_tokens_example([access_token] * 3)

    # Example 7: FastAPI Pattern
    await fastapi_pattern_example()

    print("\\n" + "=" * 60)
    print("All async examples completed!")
    print("=" * 60)


if __name__ == "__main__":
    # Run the async main function
    asyncio.run(main())
