"""Adversarial ID-token-substitution test for the middleware (F-07).

``TokenValidationMiddleware`` discriminates ID tokens from access tokens ONLY
by the presence of ``_ID_TOKEN_ONLY_CLAIMS = ("nonce", "at_hash", "c_hash")``.
All three are OPTIONAL for the authorization-code flow, so a code-flow ID token
routinely carries none of them. With ``audience`` defaulted to the client_id,
such an ID token's ``aud`` matches, it passes ``validate_token`` (valid
signature/issuer/audience), and the guard's ``any(...)`` is False — so an
OP-authenticated user can replay their own ID token as ``Authorization:
Bearer`` and reach every protected route without a client-authorized access
token.

The existing ``test_id_token_rejected_as_access_token`` only covers the
nonce-PRESENT case; this exercises the real gap. ``validate_token`` is mocked
to return the claims a genuine code-flow ID token would yield after passing
signature/iss/aud validation — isolating the middleware's type-confusion guard,
matching the existing harness. It asserts 401 and XFAILs (today: 200) until a
positive access-token marker (e.g. ``typ:at+jwt`` or a distinct RS audience)
is required.
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
    reason="F-07: a code-flow ID token (no nonce/at_hash/c_hash, aud=client_id) "
    "is accepted as a bearer access token",
)
async def test_codeflow_id_token_without_hash_claims_is_rejected(monkeypatch):
    # A valid code-flow ID token: correct iss/sig/aud, but NONE of the
    # ID-token-only marker claims the guard keys on.
    id_token_claims = {
        "sub": "user-1",
        "aud": "cid",
        "iss": "https://op",
        "exp": 9999999999,
    }
    async with _client(
        _app(monkeypatch, AsyncMock(return_value=id_token_claims))
    ) as client:
        resp = await client.get("/me", headers={"Authorization": "Bearer idtok"})
    assert resp.status_code == 401
