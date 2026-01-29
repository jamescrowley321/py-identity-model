"""
FastAPI dependency injection functions for Descope-specific claims and authorization.

This module extends the base FastAPI dependencies with Descope-specific functionality
for roles, permissions, and custom claims.
"""

from collections.abc import Callable

from fastapi import Depends, HTTPException, status

# Import base dependencies from generic FastAPI example
from examples.fastapi.dependencies import (
    get_claims,
    get_current_user,
    get_token,
    require_scope,
)


__all__ = [
    # Re-export base dependencies
    "get_claims",
    "get_current_user",
    "get_descope_permissions",
    # Descope-specific dependencies
    "get_descope_roles",
    "get_token",
    "require_descope_permission",
    "require_descope_role",
    "require_scope",
]


# Descope-Specific Dependencies


def get_descope_roles(claims: dict = Depends(get_claims)) -> list:
    """
    Dependency to extract Descope roles from token claims.

    Descope includes roles in the token when requested with the 'descope.claims' scope.
    Roles can be in different claim formats depending on Descope configuration.

    Args:
        claims: The token claims dictionary

    Returns:
        list: List of role names

    Example:
        ```python
        @app.get("/my-roles")
        async def get_my_roles(roles: list = Depends(get_descope_roles)):
            return {"roles": roles}
        ```
    """
    # Descope can store roles in different claim formats
    # Check common claim names for roles
    roles = claims.get("roles", [])

    # Handle string format (space-separated or comma-separated)
    if isinstance(roles, str):
        # Try space-separated first, then comma-separated
        if " " in roles:
            return roles.split()
        if "," in roles:
            return [r.strip() for r in roles.split(",")]
        # Single role
        return [roles] if roles else []

    # Handle list format
    if isinstance(roles, list):
        return roles

    return []


def get_descope_permissions(claims: dict = Depends(get_claims)) -> list:
    """
    Dependency to extract Descope permissions from token claims.

    Descope includes permissions in the token when requested with the 'descope.claims' scope.
    Permissions represent fine-grained access control (e.g., 'users.create', 'users.delete').

    Args:
        claims: The token claims dictionary

    Returns:
        list: List of permission names

    Example:
        ```python
        @app.get("/my-permissions")
        async def get_my_permissions(
            perms: list = Depends(get_descope_permissions),
        ):
            return {"permissions": perms}
        ```
    """
    # Descope can store permissions in different claim formats
    permissions = claims.get("permissions", [])

    # Handle string format (space-separated or comma-separated)
    if isinstance(permissions, str):
        if " " in permissions:
            return permissions.split()
        if "," in permissions:
            return [p.strip() for p in permissions.split(",")]
        return [permissions] if permissions else []

    # Handle list format
    if isinstance(permissions, list):
        return permissions

    return []


def require_descope_role(role: str) -> Callable[..., None]:
    """
    Factory function to create a dependency that requires a specific Descope role.

    Args:
        role: The required Descope role name

    Returns:
        callable: A dependency function that validates the role

    Raises:
        HTTPException: If the required role is not present

    Example:
        ```python
        require_admin = require_descope_role("admin")


        @app.get("/admin/dashboard")
        async def admin_dashboard(_: None = Depends(require_admin)):
            return {"message": "Welcome to admin dashboard"}
        ```
    """

    def _check_role(roles: list = Depends(get_descope_roles)) -> None:
        if role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required Descope role: {role}",
            )

    return _check_role


def require_descope_permission(permission: str) -> Callable[..., None]:
    """
    Factory function to create a dependency that requires a specific Descope permission.

    Args:
        permission: The required Descope permission (e.g., 'users.create')

    Returns:
        callable: A dependency function that validates the permission

    Raises:
        HTTPException: If the required permission is not present

    Example:
        ```python
        require_user_create = require_descope_permission("users.create")


        @app.post("/users")
        async def create_user(
            user_data: dict, _: None = Depends(require_user_create)
        ):
            return {"message": "User created"}
        ```
    """

    def _check_permission(
        permissions: list = Depends(get_descope_permissions),
    ) -> None:
        if permission not in permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required Descope permission: {permission}",
            )

    return _check_permission
