"""Adversarial sender-constraint test for the middleware (F-02).

``validate_certificate_binding`` (RFC 8705 §3) exists but is never wired into
``validate_token`` or the middleware. The middleware accepts the ``bearer``
scheme only and never inspects ``cnf``. So a certificate-bound access token
(``cnf.x5t#S256`` present) stolen and replayed as a PLAIN ``Bearer`` token —
with no client certificate on the connection — is accepted identically to an
unbound bearer token, silently downgrading the RFC 8705 sender constraint and
making bound tokens fully replayable.

``validate_token`` is mocked to return the bound token's claims (as it would
after signature/iss/aud validation); the middleware, presented no client cert,
must reject a ``cnf``-bound token offered as bearer. Asserts 401 and XFAILs
(today: 200) until sender-constraint enforcement is wired in.
"""

from unittest.mock import AsyncMock

from fastapi import Depends, FastAPI
import httpx
import pytest

from fastapi_identity_model import TokenValidationMiddleware, get_claims
import fastapi_identity_model.middleware as mw


pytestmark = pytest.mark.unit

DISCOVERY_URL = "https://op/.well-known/openid-configuration"


def _app(monkeypatch, validate) -> FastAPI:
    monkeypatch.setattr(mw, "validate_token", validate)
    app = FastAPI()
    app.add_middleware(
        TokenValidationMiddleware,
        discovery_url=DISCOVERY_URL,
        audience="cid",
        excluded_paths=["/health"],
    )

    @app.get("/me")
    async def me(claims: dict = Depends(get_claims)):
        return claims

    return app


def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    )


@pytest.mark.xfail(
    strict=True,
    reason="F-02: an mTLS cnf.x5t#S256-bound token is accepted as a plain bearer "
    "with no client certificate (sender constraint not enforced)",
)
async def test_cnf_bound_token_presented_as_bearer_is_rejected(monkeypatch):
    bound_claims = {
        "sub": "user-1",
        "aud": "cid",
        "iss": "https://op",
        # RFC 8705 certificate-binding confirmation method.
        "cnf": {"x5t#S256": "Gms6oPFq0v2Y7d3f4a1b2c3d4e5f6g7h8i9j0kLmNoP"},
    }
    async with _client(
        _app(monkeypatch, AsyncMock(return_value=bound_claims))
    ) as client:
        # No client certificate is presented over ASGI — the bound token is a
        # stolen replay.
        resp = await client.get("/me", headers={"Authorization": "Bearer boundtok"})
    assert resp.status_code == 401
