"""
FastAPI example for py-identity-model.

This package demonstrates how to integrate py-identity-model with FastAPI
for OAuth2/OIDC authentication and authorization.
"""

__all__ = [
    "TokenValidationMiddleware",
    "get_current_user",
    "get_claims",
    "get_token",
    "get_claim_value",
    "get_claim_values",
    "require_claim",
    "require_scope",
]
