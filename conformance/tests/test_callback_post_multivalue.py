"""Tests for the form_post callback handler's multi-value preservation.

The OIDC form_post response mode (response_mode=form_post) delivers the
authorization response as a POST body to the RP's callback URL. Single-
value fields like ``code``, ``state``, ``id_token`` are the common case,
but starlette's ``FormData`` is a multi-dict and can carry repeated keys.
``dict(form_data)`` silently drops every value except the first for a
repeated key, which would corrupt any legitimate multi-value submission.

These tests exercise the POST /callback handler end-to-end via a TestClient,
asserting that multi-value form fields survive the round-trip through
``urlencode`` and reach ``_handle_callback`` intact.

The parser/query construction is the surface under test; the downstream
``_handle_callback`` pipeline is mocked so the tests don't need to set up
a full OIDC session state.
"""

from __future__ import annotations

from unittest.mock import patch
from urllib.parse import urlencode

import app as harness_app
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient


HTTP_OK = 200


def _capture_callback_url() -> tuple[list[str], object]:
    """Patch ``_handle_callback`` to record the callback_url argument.

    Returns ``(captured_urls, patcher)`` so tests can stop the patch.
    """
    captured: list[str] = []

    def fake_handle_callback(callback_url: str) -> JSONResponse:
        captured.append(callback_url)
        return JSONResponse(content={"status": "ok"})

    patcher = patch.object(
        harness_app, "_handle_callback", side_effect=fake_handle_callback
    )
    return captured, patcher


def test_callback_post_preserves_single_value_fields() -> None:
    """Happy-path single-value fields round-trip through urlencode correctly."""
    captured, patcher = _capture_callback_url()
    with patcher:
        client = TestClient(harness_app.app)
        response = client.post(
            "/callback",
            data={"code": "abc123", "state": "xyz"},
        )

    assert response.status_code == HTTP_OK
    assert len(captured) == 1
    url = captured[0]
    # Order is not guaranteed, but both key/value pairs must appear
    assert "code=abc123" in url
    assert "state=xyz" in url


def test_callback_post_preserves_repeated_field_values() -> None:
    """A form field submitted twice must appear twice in the callback URL.

    This is the regression test for the dict(form_data) → multi_items fix.
    With the old code, both ``scope`` values would collapse into just the
    last one, silently corrupting the downstream _handle_callback input.

    We construct the request body as a pre-encoded urlencoded string so
    the repeated key survives transit. httpx's ``data=`` mapping would
    collapse the duplicate at the client side before the request leaves
    the TestClient — we need the repeated keys to reach starlette's
    FormData parser so the server-side multi_items() path is exercised.
    """

    body = urlencode([("scope", "openid"), ("scope", "profile"), ("code", "abc")])
    captured, patcher = _capture_callback_url()
    with patcher:
        client = TestClient(harness_app.app)
        response = client.post(
            "/callback",
            content=body,
            headers={"content-type": "application/x-www-form-urlencoded"},
        )

    assert response.status_code == HTTP_OK
    assert len(captured) == 1
    url = captured[0]
    # Both scope values must be present. urlencode on a list of pairs
    # preserves them; dict() would have dropped "openid".
    assert "scope=openid" in url
    assert "scope=profile" in url
    assert "code=abc" in url


def test_callback_post_handles_empty_form() -> None:
    """An empty POST body must not crash the handler."""
    captured, patcher = _capture_callback_url()
    with patcher:
        client = TestClient(harness_app.app)
        response = client.post("/callback", data={})

    assert response.status_code == HTTP_OK
    assert len(captured) == 1
    # The callback URL should still be well-formed, just with no query params
    assert captured[0].endswith("/callback?")


def test_callback_post_urlencodes_special_characters() -> None:
    """State values with =, &, space, and URL-unsafe chars must survive."""
    captured, patcher = _capture_callback_url()
    with patcher:
        client = TestClient(harness_app.app)
        response = client.post(
            "/callback",
            data={"state": "with space&eq=chars", "code": "a+b/c"},
        )

    assert response.status_code == HTTP_OK
    assert len(captured) == 1
    url = captured[0]
    # urlencode should percent-encode special chars
    assert "with+space" in url or "with%20space" in url
    assert "%26" in url  # ampersand
    assert "%3D" in url  # equals sign inside value
