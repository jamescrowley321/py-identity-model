"""
Integration tests for the FastAPI OAuth/OIDC example.

These tests verify that the FastAPI application correctly integrates with
an identity server and properly validates tokens.
"""

import os
import time
from typing import Optional

import requests

# Configuration from environment
DISCOVERY_URL = os.getenv(
    "DISCOVERY_URL", "https://localhost:5001/.well-known/openid-configuration"
)
FASTAPI_URL = os.getenv("FASTAPI_URL", "http://localhost:8000")
CLIENT_ID = os.getenv("CLIENT_ID", "py-identity-model-client")
CLIENT_SECRET = os.getenv("CLIENT_SECRET", "py-identity-model-secret")
AUDIENCE = os.getenv("AUDIENCE", "py-identity-model")
SCOPE = os.getenv("SCOPE", "py-identity-model")


def get_access_token() -> Optional[str]:
    """Get an access token from the identity server using client credentials."""
    print(f"🔍 Getting discovery document from {DISCOVERY_URL}")

    # Disable SSL verification for local testing
    session = requests.Session()
    session.verify = False

    try:
        disco_response = session.get(DISCOVERY_URL, timeout=10)
        disco_response.raise_for_status()
        disco_data = disco_response.json()

        token_endpoint = disco_data.get("token_endpoint")
        if not token_endpoint:
            print("❌ Token endpoint not found in discovery document")
            return None

        print(f"🎫 Requesting token from {token_endpoint}")

        token_response = session.post(
            token_endpoint,
            data={
                "grant_type": "client_credentials",
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "scope": SCOPE,
            },
            timeout=10,
        )
        token_response.raise_for_status()
        token_data = token_response.json()

        access_token = token_data.get("access_token")
        if access_token:
            print("✅ Successfully obtained access token")
            return access_token
        else:
            print("❌ No access token in response")
            return None

    except Exception as e:
        print(f"❌ Error getting access token: {e}")
        return None


def wait_for_service(url: str, max_attempts: int = 30) -> bool:
    """Wait for a service to become available."""
    print(f"⏳ Waiting for service at {url}")
    for attempt in range(max_attempts):
        try:
            response = requests.get(url, timeout=5, verify=False)
            if response.status_code < 500:
                print(f"✅ Service available at {url}")
                return True
        except requests.exceptions.RequestException:
            pass

        if attempt < max_attempts - 1:
            time.sleep(2)

    print(f"❌ Service at {url} did not become available")
    return False


def test_public_endpoints():
    """Test public endpoints that don't require authentication."""
    print("\n🧪 Testing public endpoints...")

    # Test root endpoint
    response = requests.get(f"{FASTAPI_URL}/")
    assert response.status_code == 200, (
        f"Root endpoint failed: {response.text}"
    )
    data = response.json()
    assert "message" in data
    print("✅ Root endpoint works")

    # Test health endpoint
    response = requests.get(f"{FASTAPI_URL}/health")
    assert response.status_code == 200, (
        f"Health endpoint failed: {response.text}"
    )
    data = response.json()
    assert data["status"] == "healthy"
    print("✅ Health endpoint works")


def test_protected_endpoints_without_token():
    """Test that protected endpoints reject requests without tokens."""
    print("\n🧪 Testing protected endpoints without token...")

    protected_endpoints = [
        "/api/me",
        "/api/claims",
        "/api/token-info",
        "/api/profile",
        "/api/data",
    ]

    for endpoint in protected_endpoints:
        response = requests.get(f"{FASTAPI_URL}{endpoint}")
        assert response.status_code == 401, (
            f"Expected 401 for {endpoint} without token, got {response.status_code}"
        )
        print(f"✅ {endpoint} correctly rejects request without token")


def test_protected_endpoints_with_invalid_token():
    """Test that protected endpoints reject requests with invalid tokens."""
    print("\n🧪 Testing protected endpoints with invalid token...")

    headers = {"Authorization": "Bearer invalid-token-123"}
    response = requests.get(f"{FASTAPI_URL}/api/me", headers=headers)
    assert response.status_code == 401, (
        f"Expected 401 for invalid token, got {response.status_code}"
    )
    print("✅ Protected endpoint correctly rejects invalid token")


def test_protected_endpoints_with_valid_token(token: str):
    """Test protected endpoints with a valid token."""
    print("\n🧪 Testing protected endpoints with valid token...")

    headers = {"Authorization": f"Bearer {token}"}

    # Test /api/me
    response = requests.get(f"{FASTAPI_URL}/api/me", headers=headers)
    assert response.status_code == 200, f"/api/me failed: {response.text}"
    data = response.json()
    assert data["authenticated"] is True, (
        f"Expected authenticated=True, got {data.get('authenticated')}"
    )
    assert data["authentication_type"] == "Bearer", (
        f"Expected authentication_type='Bearer', got {data.get('authentication_type')}"
    )
    print("✅ /api/me works with valid token")

    # Test /api/claims
    response = requests.get(f"{FASTAPI_URL}/api/claims", headers=headers)
    assert response.status_code == 200, f"/api/claims failed: {response.text}"
    data = response.json()
    assert "claims" in data
    assert "scope" in data["claims"] or "scp" in data["claims"]
    print("✅ /api/claims works with valid token")

    # Test /api/token-info
    response = requests.get(f"{FASTAPI_URL}/api/token-info", headers=headers)
    assert response.status_code == 200, (
        f"/api/token-info failed: {response.text}"
    )
    data = response.json()
    assert "token_length" in data
    assert data["token_length"] > 0
    print("✅ /api/token-info works with valid token")

    # Test /api/profile
    response = requests.get(f"{FASTAPI_URL}/api/profile", headers=headers)
    assert response.status_code == 200, f"/api/profile failed: {response.text}"
    data = response.json()
    assert "user_id" in data
    print("✅ /api/profile works with valid token")

    # Test /api/data (requires scope)
    response = requests.get(f"{FASTAPI_URL}/api/data", headers=headers)
    assert response.status_code == 200, f"/api/data failed: {response.text}"
    data = response.json()
    assert "data" in data
    assert len(data["data"]) > 0
    print("✅ /api/data works with valid token and correct scope")


def test_scope_based_authorization(token: str):
    """Test scope-based authorization."""
    print("\n🧪 Testing scope-based authorization...")

    headers = {"Authorization": f"Bearer {token}"}

    # Test endpoint requiring write scope (should fail with default token)
    response = requests.post(
        f"{FASTAPI_URL}/api/data",
        headers=headers,
        params={"name": "Test Item"},
    )
    # This should fail because the token doesn't have write scope
    assert response.status_code == 403, "Expected 403 for missing write scope"
    print("✅ Write endpoint correctly rejects token without write scope")


def test_admin_endpoints_without_role(token: str):
    """Test that admin endpoints reject tokens without admin role."""
    print("\n🧪 Testing admin endpoints without admin role...")

    headers = {"Authorization": f"Bearer {token}"}

    # Test admin endpoints (should fail without admin role)
    response = requests.delete(
        f"{FASTAPI_URL}/api/admin/users/123",
        headers=headers,
    )
    assert response.status_code == 403, (
        f"Expected 403 for missing admin role, got {response.status_code}: {response.text}"
    )
    print(
        "✅ Admin delete endpoint correctly rejects token without admin role"
    )

    response = requests.get(f"{FASTAPI_URL}/api/admin/stats", headers=headers)
    assert response.status_code == 403, "Expected 403 for missing admin role"
    print("✅ Admin stats endpoint correctly rejects token without admin role")


def run_tests():
    """Run all integration tests."""
    print("=" * 60)
    print("FastAPI OAuth/OIDC Integration Tests")
    print("=" * 60)

    # Disable SSL warnings for local testing
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Wait for services to be ready
    if not wait_for_service(FASTAPI_URL):
        print("❌ FastAPI service not available")
        return 1

    if not wait_for_service(DISCOVERY_URL):
        print("❌ Identity server not available")
        return 1

    # Get access token
    token = get_access_token()
    if not token:
        print("❌ Failed to obtain access token")
        return 1

    try:
        # Run all tests
        test_public_endpoints()
        test_protected_endpoints_without_token()
        test_protected_endpoints_with_invalid_token()
        test_protected_endpoints_with_valid_token(token)
        test_scope_based_authorization(token)
        test_admin_endpoints_without_role(token)

        print("\n" + "=" * 60)
        print("✅ All tests passed!")
        print("=" * 60)
        return 0

    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        import traceback

        traceback.print_exc()
        return 1
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit_code = run_tests()
    exit(exit_code)
