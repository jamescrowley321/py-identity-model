"""
Example FastAPI application demonstrating OAuth2/OIDC authentication.

This example shows how to use py-identity-model with FastAPI to:
- Validate JWT tokens using middleware
- Protect routes with authentication
- Access user claims via dependency injection
- Enforce authorization based on claims and scopes
"""

from typing import List
from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import JSONResponse
import uvicorn

from py_identity_model.identity import ClaimsPrincipal

from middleware import TokenValidationMiddleware
from dependencies import (
    get_current_user,
    get_claims,
    get_token,
    get_claim_value,
    get_claim_values,
    require_claim,
    require_scope,
)


# Configuration - can be overridden by environment variables
import os

DISCOVERY_URL = os.getenv(
    "DISCOVERY_URL", "https://localhost:5001/.well-known/openid-configuration"
)
AUDIENCE = os.getenv("AUDIENCE", "py-identity-model")

# Create FastAPI app
app = FastAPI(
    title="py-identity-model FastAPI Example",
    description="Example API demonstrating OAuth2/OIDC authentication with py-identity-model",
    version="1.0.0",
)

# Add token validation middleware
app.add_middleware(
    TokenValidationMiddleware,
    discovery_url=DISCOVERY_URL,
    audience=AUDIENCE,
    excluded_paths=["/", "/health", "/docs", "/openapi.json"],
)


# Public routes (no authentication required)
@app.get("/", tags=["public"])
async def root():
    """Public root endpoint."""
    return {
        "message": "Welcome to the py-identity-model FastAPI example",
        "docs": "/docs",
        "authentication": "Bearer token required for protected endpoints",
    }


@app.get("/health", tags=["public"])
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}


# Protected routes (authentication required)
@app.get("/api/me", tags=["protected"])
async def get_current_user_info(user: ClaimsPrincipal = Depends(get_current_user)):
    """
    Get information about the currently authenticated user.

    Returns the user's claims principal information.
    """
    return {
        "authenticated": user.identity.is_authenticated,
        "authentication_type": user.identity.authentication_type,
        "name": user.identity.name,
        "claims_count": len(user.identity.claims),
    }


@app.get("/api/claims", tags=["protected"])
async def get_user_claims(claims: dict = Depends(get_claims)):
    """
    Get all claims from the authenticated user's token.

    Returns the raw claims dictionary from the validated JWT.
    """
    return {"claims": claims}


@app.get("/api/token-info", tags=["protected"])
async def get_token_info(token: str = Depends(get_token)):
    """
    Get information about the current access token.

    Returns basic information about the JWT token.
    """
    return {
        "token_length": len(token),
        "token_preview": f"{token[:20]}...{token[-20:]}",
    }


# Routes using specific claim extraction
get_user_id = get_claim_value("sub")
get_user_email = get_claim_value("email")
get_user_roles = get_claim_values("role")


@app.get("/api/profile", tags=["protected"])
async def get_profile(
    user_id: str = Depends(get_user_id),
    email: str = Depends(get_user_email),
    roles: List[str] = Depends(get_user_roles),
):
    """
    Get the user's profile information from specific claims.

    Demonstrates extracting individual claims using dependency injection.
    """
    return {
        "user_id": user_id,
        "email": email or "Not provided",
        "roles": roles if roles else [],
    }


# Routes with scope-based authorization
require_read_scope = require_scope("py-identity-model")
require_write_scope = require_scope("py-identity-model.write")


@app.get("/api/data", tags=["protected"], dependencies=[Depends(require_read_scope)])
async def get_data():
    """
    Get data (requires 'py-identity-model' scope).

    This endpoint is protected by scope-based authorization.
    """
    return {
        "data": [
            {"id": 1, "name": "Item 1"},
            {"id": 2, "name": "Item 2"},
            {"id": 3, "name": "Item 3"},
        ]
    }


@app.post("/api/data", tags=["protected"], dependencies=[Depends(require_write_scope)])
async def create_data(name: str):
    """
    Create data (requires 'py-identity-model.write' scope).

    This endpoint requires elevated permissions via the write scope.
    """
    return {
        "message": "Data created successfully",
        "data": {"id": 4, "name": name},
    }


# Routes with claim-based authorization
require_admin_role = require_claim("role", "admin")


@app.delete(
    "/api/admin/users/{user_id}",
    tags=["admin"],
    dependencies=[Depends(require_admin_role)],
)
async def delete_user(user_id: str):
    """
    Delete a user (requires 'admin' role).

    This endpoint is restricted to users with the admin role claim.
    """
    return {
        "message": f"User {user_id} deleted successfully",
        "deleted_by": "admin",
    }


@app.get("/api/admin/stats", tags=["admin"], dependencies=[Depends(require_admin_role)])
async def get_admin_stats():
    """
    Get admin statistics (requires 'admin' role).

    This endpoint is restricted to administrators.
    """
    return {
        "total_users": 42,
        "active_sessions": 15,
        "requests_today": 1337,
    }


# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Custom error handler for HTTP exceptions."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
        },
        headers=exc.headers,
    )


if __name__ == "__main__":
    print("🚀 Starting FastAPI application...")
    print(f"📍 Discovery URL: {DISCOVERY_URL}")
    print(f"🎯 Expected Audience: {AUDIENCE}")
    print("\n💡 To get a token, run: python ../generate_token.py")
    print("\n📚 API documentation: http://localhost:8000/docs")
    print("\n🔐 Example request:")
    print('   curl -H "Authorization: Bearer <token>" http://localhost:8000/api/me')

    uvicorn.run(app, host="0.0.0.0", port=8000)
