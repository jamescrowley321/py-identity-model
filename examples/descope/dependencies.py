"""
FastAPI dependency injection functions for Descope-specific claims and authorization.

These dependencies extend the generic py-identity-model dependencies with
Descope-specific functionality for roles, permissions, and custom claims.
"""

from collections.abc import Callable

from fastapi import Depends, HTTPException, Request, status

from py_identity_model.identity import ClaimsPrincipal


# Error message constants
_NOT_AUTHENTICATED_MSG = "Not authenticated"


def get_current_user(request: Request) -> ClaimsPrincipal:
    """
    Dependency to get the current authenticated user as a ClaimsPrincipal.

    This dependency should be used after the TokenValidationMiddleware has
    validated the token and attached the user to the request state.

    Args:
        request: The FastAPI request object

    Returns:
        ClaimsPrincipal: The authenticated user principal

    Raises:
        HTTPException: If no authenticated user is found

    Example:
        ```python
        @app.get("/profile")
        async def get_profile(
            user: ClaimsPrincipal = Depends(get_current_user),
        ):
            return {"user_id": user.identity.name}
        ```
    """
    if not hasattr(request.state, "user"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_NOT_AUTHENTICATED_MSG,
            headers={"WWW-Authenticate": "Bearer"},
        )

    return request.state.user


def get_claims(request: Request) -> dict:
    """
    Dependency to get all claims from the validated token.

    Args:
        request: The FastAPI request object

    Returns:
        dict: Dictionary of all claims from the token

    Raises:
        HTTPException: If no claims are found

    Example:
        ```python
        @app.get("/claims")
        async def get_all_claims(claims: dict = Depends(get_claims)):
            return {"claims": claims}
        ```
    """
    if not hasattr(request.state, "claims"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_NOT_AUTHENTICATED_MSG,
            headers={"WWW-Authenticate": "Bearer"},
        )

    return request.state.claims


def get_token(request: Request) -> str:
    """
    Dependency to get the raw JWT token.

    Args:
        request: The FastAPI request object

    Returns:
        str: The raw JWT token

    Raises:
        HTTPException: If no token is found

    Example:
        ```python
        @app.get("/token-info")
        async def get_token_info(token: str = Depends(get_token)):
            return {"token_length": len(token)}
        ```
    """
    if not hasattr(request.state, "token"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_NOT_AUTHENTICATED_MSG,
            headers={"WWW-Authenticate": "Bearer"},
        )

    return request.state.token


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


def require_scope(scope: str) -> Callable[..., None]:
    """
    Factory function to create a dependency that requires a specific OAuth scope.

    Args:
        scope: The required scope

    Returns:
        callable: A dependency function that validates the scope

    Raises:
        HTTPException: If the required scope is not present

    Example:
        ```python
        require_read_scope = require_scope("openid")


        @app.get("/data")
        async def get_data(_: None = Depends(require_read_scope)):
            return {"data": "sensitive information"}
        ```
    """

    def _check_scope(claims: dict = Depends(get_claims)) -> None:
        # Scopes can be in 'scope' (space-separated string) or 'scp' (array)
        scope_claim = claims.get("scope") or claims.get("scp")

        if not scope_claim:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No scope claim found in token",
            )

        # Handle space-separated string or array
        if isinstance(scope_claim, str):
            scopes = scope_claim.split()
        else:
            scopes = scope_claim

        if scope not in scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Required scope '{scope}' not found",
            )

    return _check_scope
