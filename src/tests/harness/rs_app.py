"""Greenfield FastAPI resource server for the token-blaster harness (TH-1.2).

A minimal RS that mounts ``TokenValidationMiddleware`` and guards routes with
``require_scope``. All configuration comes from ``RS_*`` environment variables
so uvicorn ``--workers N`` forked workers each re-import this module and rebuild
an identical app (the workers are forked *after* import-string resolution, so
they cannot share a closure — only the env).

This is the ONLY harness module that imports FastAPI / fastapi-identity-model.
It is excluded from the root pyrefly lint env (see ``[tool.pyrefly]
project_excludes`` in ``pyproject.toml``) because that env installs only
py-identity-model and cannot resolve the fastapi stack; it is exercised via
``make test-harness-rs`` under ``uv run --all-packages``.
"""

from __future__ import annotations

import os

from fastapi import Depends, FastAPI

from fastapi_identity_model import (
    Claims,
    CurrentUser,
    TokenValidationMiddleware,
    require_scope,
)


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _excluded_paths() -> list[str] | None:
    """Parse ``RS_EXCLUDED_PATHS`` (comma-separated) or return ``None`` so the
    middleware falls back to its own defaults (which include ``/health``)."""
    raw = os.environ.get("RS_EXCLUDED_PATHS")
    if raw is None:
        return None
    return [p for p in raw.split(",") if p]


def create_app() -> FastAPI:
    """Build the resource-server app from ``RS_*`` env config.

    Required env: ``RS_DISCOVERY_URL``, ``RS_AUDIENCE``.
    Optional env: ``RS_REQUIRE_SCOPE`` (default ``api``),
    ``RS_REQUIRE_ACCESS_TOKEN_MARKER`` (bool, F-07 opt-in),
    ``RS_EXCLUDED_PATHS`` (comma-separated).
    """
    discovery_url = os.environ["RS_DISCOVERY_URL"]
    audience = os.environ["RS_AUDIENCE"]
    required_scope = os.environ.get("RS_REQUIRE_SCOPE", "api")

    app = FastAPI(title="token-harness-rs")
    app.add_middleware(
        TokenValidationMiddleware,
        discovery_url=discovery_url,
        audience=audience,
        excluded_paths=_excluded_paths(),
        require_access_token_marker=_truthy(
            os.environ.get("RS_REQUIRE_ACCESS_TOKEN_MARKER")
        ),
    )

    @app.get("/health")
    def health() -> dict:
        # Excluded from auth (middleware default) — the readiness probe target.
        return {"status": "ok"}

    @app.get("/protected", dependencies=[Depends(require_scope(required_scope))])
    def protected(claims: Claims) -> dict:
        # Reached only after the middleware validated the token AND the token
        # carries ``required_scope`` (else require_scope raises 403).
        return {
            "sub": claims.get("sub"),
            "scope": claims.get("scope") or claims.get("scp"),
        }

    @app.get("/whoami")
    def whoami(user: CurrentUser) -> dict:
        identity = user.identity
        return {"name": identity.name if identity is not None else None}

    return app


# Module-level app so uvicorn can boot it by import string
# (``src.tests.harness.rs_app:app``) and forked workers re-import identically.
app = create_app()
