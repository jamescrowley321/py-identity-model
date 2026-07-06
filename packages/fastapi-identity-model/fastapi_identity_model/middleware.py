"""
FastAPI middleware for OAuth2/OIDC token validation.

This module provides middleware components for validating Bearer tokens
in FastAPI applications using py-identity-model.
"""

from collections.abc import Callable
import logging

from fastapi import Request, status  # type: ignore[attr-defined]
from jwt import InvalidTokenError
from starlette.middleware.base import (
    BaseHTTPMiddleware,  # type: ignore[attr-defined]
)
from starlette.responses import (  # type: ignore[attr-defined]
    JSONResponse,
    Response,
)

from py_identity_model import (
    NetworkException,
    PyIdentityModelException,
    TokenValidationConfig,
    to_principal,
)
from py_identity_model.aio import validate_token


logger = logging.getLogger("fastapi_identity_model")

# Expected number of parts in "Bearer <token>" authorization header
_BEARER_HEADER_PART_COUNT = 2

# Claims that only ever appear in an ID token (OIDC Core 1.0 §2, §3.1.3.6).
# Their presence means an ID token was presented where an access token is
# expected — reject it to prevent token-substitution at the resource server.
_ID_TOKEN_ONLY_CLAIMS = ("nonce", "at_hash", "c_hash")


class TokenValidationMiddleware(BaseHTTPMiddleware):
    """
    Middleware for validating Bearer tokens on incoming requests.

    This middleware automatically validates JWT tokens from the Authorization header
    and attaches the validated claims to the request state.

    Args:
        app: The FastAPI application
        discovery_url: The OpenID Connect discovery document URL
        audience: Expected audience claim in the token. Required — a ``None``
            audience does not enforce ``aud`` for tokens that omit the claim,
            which on a shared multi-tenant issuer accepts tokens minted for
            other clients.
        excluded_paths: Paths that skip token validation. A path matches if it
            equals an entry or is a subpath of one (``/docs`` also covers
            ``/docs/oauth2-redirect``). Pass ``[]`` to exclude nothing. When
            omitted, defaults to ``/docs``, ``/openapi.json``, ``/health``.
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
        if not audience:
            raise ValueError(
                "TokenValidationMiddleware requires a non-empty 'audience'; a "
                "None/empty audience skips aud enforcement for aud-less tokens."
            )
        self.discovery_url = discovery_url
        self.audience = audience
        # ``is not None`` (not truthiness) so an explicit [] means "exclude
        # nothing" instead of silently re-enabling the defaults.
        self.excluded_paths = (
            excluded_paths
            if excluded_paths is not None
            else ["/docs", "/openapi.json", "/health"]
        )
        self.custom_claims_validator = custom_claims_validator

    def _is_excluded(self, path: str) -> bool:
        """Whether *path* equals or is a subpath of an excluded entry.

        A bare ``/`` entry matches only the root, never as a subpath prefix
        (otherwise it would exclude every path).
        """
        for entry in self.excluded_paths:
            if path == entry:
                return True
            prefix = entry.rstrip("/")
            if prefix and path.startswith(prefix + "/"):
                return True
        return False

    @staticmethod
    def _unauthorized(detail: str) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": detail},
            headers={"WWW-Authenticate": "Bearer"},
        )

    def _extract_bearer_token(self, request: Request) -> str | JSONResponse:
        """Return the bearer token, or an error ``JSONResponse`` if absent/malformed."""
        authorization = request.headers.get("Authorization")
        if not authorization:
            return self._unauthorized("Missing Authorization header")
        parts = authorization.split()
        if len(parts) != _BEARER_HEADER_PART_COUNT or parts[0].lower() != "bearer":
            return self._unauthorized(
                "Invalid Authorization header format. Expected: Bearer <token>"
            )
        return parts[1]

    async def _authenticate(self, request: Request, token: str) -> JSONResponse | None:
        """Validate *token* and attach claims; return an error response or None."""
        try:
            claims = await validate_token(
                jwt=token,
                token_validation_config=TokenValidationConfig(
                    perform_disco=True,
                    audience=self.audience,
                    claims_validator=self.custom_claims_validator,
                ),
                disco_doc_address=self.discovery_url,
            )
            # Reject an ID token presented as an access token. With audience
            # defaulted to client_id, an ID token's aud matches, so type must
            # be discriminated on ID-token-only claims.
            if any(c in claims for c in _ID_TOKEN_ONLY_CLAIMS):
                return self._unauthorized("ID token cannot be used as an access token")
            request.state.user = to_principal(claims)
            request.state.claims = claims
            request.state.token = token
            return None
        except NetworkException:
            # Discovery/JWKS/network fetch failure is a transient server fault,
            # not an authentication decision — surface 5xx so callers retry
            # instead of treating a provider outage as a bad token.
            logger.exception("Network error during token validation")
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"detail": "Authentication temporarily unavailable"},
            )
        except PyIdentityModelException as e:
            return self._unauthorized(f"Token validation failed: {e!s}")
        except InvalidTokenError as e:
            # A malformed/undecodable token (e.g. raw pyjwt DecodeError from
            # header parsing during key lookup) is a client error, not a 500.
            return self._unauthorized(f"Invalid token: {e!s}")
        except Exception:
            # A genuinely unexpected (non-library) failure is a server fault,
            # not an auth decision. Surface a 500 without leaking internals.
            logger.exception("Unexpected error during token validation")
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": "Internal server error during authentication"},
            )

    async def dispatch(self, request: Request, call_next) -> Response:
        """Process the request and validate the token if required."""
        # CORS preflight carries no Authorization; excluded paths skip auth.
        if request.method == "OPTIONS" or self._is_excluded(request.url.path):
            return await call_next(request)

        token = self._extract_bearer_token(request)
        if isinstance(token, JSONResponse):
            return token

        auth_error = await self._authenticate(request, token)
        if auth_error is not None:
            return auth_error

        return await call_next(request)
