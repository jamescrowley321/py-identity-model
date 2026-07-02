"""
FastAPI middleware for OAuth2/OIDC token validation.

This module provides middleware components for validating Bearer tokens
in FastAPI applications using py-identity-model.
"""

from collections.abc import Callable
import logging

from fastapi import Request, status  # type: ignore[attr-defined]
from starlette.middleware.base import (
    BaseHTTPMiddleware,  # type: ignore[attr-defined]
)
from starlette.responses import (  # type: ignore[attr-defined]
    JSONResponse,
    Response,
)

from py_identity_model import (
    PyIdentityModelException,
    TokenValidationConfig,
    to_principal,
)
from py_identity_model.aio import validate_token


logger = logging.getLogger("fastapi_identity_model")

# Expected number of parts in "Bearer <token>" authorization header
_BEARER_HEADER_PART_COUNT = 2


class TokenValidationMiddleware(BaseHTTPMiddleware):
    """
    Middleware for validating Bearer tokens on incoming requests.

    This middleware automatically validates JWT tokens from the Authorization header
    and attaches the validated claims to the request state.

    Args:
        app: The FastAPI application
        discovery_url: The OpenID Connect discovery document URL
        audience: Expected audience claim in the token
        excluded_paths: List of paths that should skip token validation
        custom_claims_validator: Optional custom function to validate additional claims
    """

    def __init__(
        self,
        app,
        discovery_url: str,
        audience: str | None = None,
        excluded_paths: list[str] | None = None,
        custom_claims_validator: Callable | None = None,
    ):
        super().__init__(app)
        self.discovery_url = discovery_url
        self.audience = audience
        self.excluded_paths = excluded_paths or [
            "/docs",
            "/openapi.json",
            "/health",
        ]
        self.custom_claims_validator = custom_claims_validator

    async def dispatch(self, request: Request, call_next) -> Response:
        """Process the request and validate the token if required."""

        # Skip validation for excluded paths
        if request.url.path in self.excluded_paths:
            return await call_next(request)

        # Extract token from Authorization header
        authorization: str | None = request.headers.get("Authorization")

        if not authorization:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Missing Authorization header"},
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Parse Bearer token
        parts = authorization.split()
        if len(parts) != _BEARER_HEADER_PART_COUNT or parts[0].lower() != "bearer":
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={
                    "detail": "Invalid Authorization header format. Expected: Bearer <token>",
                },
                headers={"WWW-Authenticate": "Bearer"},
            )

        token = parts[1]

        # Validate token asynchronously
        try:
            validation_config = TokenValidationConfig(
                perform_disco=True,
                audience=self.audience,
                claims_validator=self.custom_claims_validator,
            )

            claims = await validate_token(
                jwt=token,
                token_validation_config=validation_config,
                disco_doc_address=self.discovery_url,
            )

            # Convert claims to ClaimsPrincipal and attach to request state
            principal = to_principal(claims)
            request.state.user = principal
            request.state.claims = claims
            request.state.token = token

        except PyIdentityModelException as e:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": f"Token validation failed: {e!s}"},
                headers={"WWW-Authenticate": "Bearer"},
            )
        except Exception:
            # An unexpected failure (e.g. transient network/JWKS error) is a
            # server fault, not an authentication decision. Surface a 500
            # without leaking internals rather than masking it as a 401.
            logger.exception("Unexpected error during token validation")
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": "Internal server error during authentication"},
            )

        # Continue processing the request
        return await call_next(request)
