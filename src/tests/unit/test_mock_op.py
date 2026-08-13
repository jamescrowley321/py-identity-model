"""Unit tests for the controllable mock OP and forged corpus (TH-1.1, #463).

Deterministic and network-free: the framework-free ASGI app is driven in-process
via ``httpx.ASGITransport``, and the *real* library
(:func:`py_identity_model.aio.validate_token`) validates minted / forged tokens
through the mock OP's discovery + JWKS documents.
"""

from __future__ import annotations

import httpx
import pytest

from py_identity_model.aio.managed_client import AsyncHTTPClient
from py_identity_model.aio.token_validation import validate_token
from py_identity_model.core.models import TokenValidationConfig
from py_identity_model.exceptions import PyIdentityModelException

from ..harness import CORPUS_AUDIENCE, MockOP, build_corpus
from ..harness import mock_op as mock_op_mod


HTTP_OK = 200
HTTP_TOO_MANY_REQUESTS = 429
HTTP_SERVICE_UNAVAILABLE = 503
PUBLISHED_KEY_COUNT = 2
OVERSIZED_PADDING = 50


def _client(mock: MockOP) -> AsyncHTTPClient:
    """An AsyncHTTPClient routed at the in-process mock OP (no network)."""
    transport = httpx.ASGITransport(app=mock.app)
    return AsyncHTTPClient(
        client=httpx.AsyncClient(
            transport=transport, base_url=mock.issuer, follow_redirects=False
        )
    )


def _validation_config() -> TokenValidationConfig:
    return TokenValidationConfig(
        perform_disco=True,
        audience=CORPUS_AUDIENCE,
        algorithms=["RS256", "ES256"],
        require_https=False,
    )


async def _validate(mock: MockOP, token: str) -> dict:
    client = _client(mock)
    try:
        return await validate_token(
            token,
            _validation_config(),
            disco_doc_address=mock.discovery_url,
            http_client=client,
        )
    finally:
        await client.close()


# -- Documents served over ASGI --------------------------------------------


async def test_discovery_document_served() -> None:
    mock = MockOP()
    transport = httpx.ASGITransport(app=mock.app)
    async with httpx.AsyncClient(transport=transport, base_url=mock.issuer) as client:
        resp = await client.get(mock.discovery_url)
    assert resp.status_code == HTTP_OK
    doc = resp.json()
    assert doc["issuer"] == mock.issuer
    assert doc["jwks_uri"] == mock.jwks_uri
    assert doc["token_endpoint"] == mock.token_endpoint


async def test_jwks_served_with_published_keys() -> None:
    mock = MockOP()
    transport = httpx.ASGITransport(app=mock.app)
    async with httpx.AsyncClient(transport=transport, base_url=mock.issuer) as client:
        resp = await client.get(mock.jwks_uri)
    kids = {k["kid"] for k in resp.json()["keys"]}
    assert mock.primary_key.kid in kids
    assert mock.ec_key.kid in kids
    assert mock.unpublished_key.kid not in kids


async def test_token_endpoint_mints_valid_token() -> None:
    mock = MockOP()
    transport = httpx.ASGITransport(app=mock.app)
    async with httpx.AsyncClient(transport=transport, base_url=mock.issuer) as client:
        resp = await client.post(
            mock.token_endpoint,
            data={"grant_type": "client_credentials", "scope": "read"},
        )
    body = resp.json()
    assert body["token_type"] == "Bearer"
    claims = await _validate(mock, body["access_token"])
    assert claims["iss"] == mock.issuer


# -- End-to-end validation of the corpus -----------------------------------


async def test_valid_token_validates_end_to_end() -> None:
    mock = MockOP()
    corpus = build_corpus(mock)
    claims = await _validate(mock, corpus["valid"].jwt)
    assert claims["scope"] == "read"


@pytest.mark.parametrize(
    "name",
    [
        "expired",
        "nbf_future",
        "wrong_iss",
        "wrong_aud",
        "tampered_sig",
        "unknown_kid",
        "wrong_alg",
        "alg_none",
    ],
)
async def test_forged_tokens_are_rejected(name: str) -> None:
    mock = MockOP()
    forged = build_corpus(mock)[name]
    assert forged.library_rejects is True
    with pytest.raises(PyIdentityModelException):
        await _validate(mock, forged.jwt)


@pytest.mark.parametrize("name", ["id_as_access", "cnf_bound", "oversized"])
async def test_library_accepted_classes_are_signature_valid(name: str) -> None:
    # These are validly signed for the audience — the library ACCEPTS them.
    # Only the RS access-token marker / require_scope layer (F-07/F-02) rejects
    # them; that distinction is proven in T302, not here.
    mock = MockOP()
    forged = build_corpus(mock)[name]
    assert forged.library_rejects is False
    claims = await _validate(mock, forged.jwt)
    assert claims["iss"] == mock.issuer


# -- Failure injection (design §2) -----------------------------------------


async def test_key_rotation_then_republish() -> None:
    mock = MockOP()
    # Rotate to the spare WITHOUT publishing -> tokens present an unknown kid.
    mock.rotate_keys(publish=False)
    token = mock.mint_access_token()["access_token"]
    with pytest.raises(PyIdentityModelException):
        await _validate(mock, token)
    # Publishing the rotated key lets the same token validate on refetch.
    mock.publish_signing_key()
    claims = await _validate(mock, token)
    assert claims["iss"] == mock.issuer


async def test_empty_jwks_control() -> None:
    mock = MockOP()
    mock.controls.serve_empty_jwks = True
    transport = httpx.ASGITransport(app=mock.app)
    async with httpx.AsyncClient(transport=transport, base_url=mock.issuer) as client:
        resp = await client.get(mock.jwks_uri)
    assert resp.json()["keys"] == []


async def test_oversized_jwks_control() -> None:
    mock = MockOP()
    mock.controls.oversized_jwks_padding = OVERSIZED_PADDING
    transport = httpx.ASGITransport(app=mock.app)
    async with httpx.AsyncClient(transport=transport, base_url=mock.issuer) as client:
        resp = await client.get(mock.jwks_uri)
    assert len(resp.json()["keys"]) == PUBLISHED_KEY_COUNT + OVERSIZED_PADDING


async def test_rate_limit_control_sets_retry_after() -> None:
    mock = MockOP()
    mock.controls.discovery_status = HTTP_TOO_MANY_REQUESTS
    mock.controls.retry_after = "3"
    transport = httpx.ASGITransport(app=mock.app)
    async with httpx.AsyncClient(transport=transport, base_url=mock.issuer) as client:
        resp = await client.get(mock.discovery_url)
    assert resp.status_code == HTTP_TOO_MANY_REQUESTS
    assert resp.headers["retry-after"] == "3"


async def test_no_store_cache_control_on_jwks() -> None:
    mock = MockOP()
    mock.controls.jwks_cache_control = "no-store"
    transport = httpx.ASGITransport(app=mock.app)
    async with httpx.AsyncClient(transport=transport, base_url=mock.issuer) as client:
        resp = await client.get(mock.jwks_uri)
    assert resp.headers["cache-control"] == "no-store"


async def test_injected_latency(monkeypatch: pytest.MonkeyPatch) -> None:
    mock = MockOP()
    slept: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)

    monkeypatch.setattr(mock_op_mod.asyncio, "sleep", fake_sleep)
    mock.controls.latency_seconds = 0.25
    transport = httpx.ASGITransport(app=mock.app)
    async with httpx.AsyncClient(transport=transport, base_url=mock.issuer) as client:
        await client.get(mock.discovery_url)
    assert slept == [0.25]


async def test_control_route_rotates_and_sets_knobs() -> None:
    mock = MockOP()
    transport = httpx.ASGITransport(app=mock.app)
    async with httpx.AsyncClient(transport=transport, base_url=mock.issuer) as client:
        resp = await client.post(
            f"{mock.issuer}/_control",
            json={
                "rotate": True,
                "publish": True,
                "jwks_status": HTTP_SERVICE_UNAVAILABLE,
            },
        )
    assert resp.json() == {"ok": True}
    assert mock.controls.jwks_status == HTTP_SERVICE_UNAVAILABLE
    assert mock.signing_key is mock.rotation_key
