"""Tests for certification-package download in conformance/run_tests.py.

These cover the pieces that make a hosted run *submission-capable*:

- ``ConformanceSuiteClient.get_certification_package`` — the REST call that
  downloads the signed zip submitted to the OpenID Foundation.
- ``ConformanceSuiteClient.create_plan`` honouring the ``publish`` setting.
- ``_should_download_package`` — the gate deciding when a package is worth
  generating (hosted suite + all tests passed only).
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from run_tests import ConformanceSuiteClient, _should_download_package


HOSTED_URL = "https://www.certification.openid.net"
LOCAL_URL = "https://localhost.emobix.co.uk:8443"


# ---------------------------------------------------------------------------
# get_certification_package
# ---------------------------------------------------------------------------


@respx.mock
def test_get_certification_package_returns_zip_bytes() -> None:
    plan_id = "abc123"
    zip_bytes = b"PK\x03\x04 fake-zip-payload"
    route = respx.get(f"{HOSTED_URL}/api/plan/{plan_id}/certificationpackage").mock(
        return_value=httpx.Response(200, content=zip_bytes)
    )

    client = ConformanceSuiteClient(HOSTED_URL, token="tok-123")
    result = client.get_certification_package(plan_id)

    assert result == zip_bytes
    assert route.called


@respx.mock
def test_get_certification_package_sends_bearer_token() -> None:
    plan_id = "plan-xyz"
    route = respx.get(f"{HOSTED_URL}/api/plan/{plan_id}/certificationpackage").mock(
        return_value=httpx.Response(200, content=b"zip")
    )

    client = ConformanceSuiteClient(HOSTED_URL, token="secret-token")
    client.get_certification_package(plan_id)

    assert route.calls.last.request.headers["Authorization"] == "Bearer secret-token"


@respx.mock
def test_get_certification_package_raises_on_error_status() -> None:
    plan_id = "missing"
    respx.get(f"{HOSTED_URL}/api/plan/{plan_id}/certificationpackage").mock(
        return_value=httpx.Response(404)
    )

    client = ConformanceSuiteClient(HOSTED_URL, token="tok")
    with pytest.raises(httpx.HTTPStatusError) as exc_info:
        client.get_certification_package(plan_id)

    assert exc_info.value.response.status_code == httpx.codes.NOT_FOUND


# ---------------------------------------------------------------------------
# create_plan publish wiring
# ---------------------------------------------------------------------------


@respx.mock
def test_create_plan_sends_publish_value() -> None:
    route = respx.post(f"{HOSTED_URL}/api/plan").mock(
        return_value=httpx.Response(200, json={"id": "p1", "modules": []})
    )

    client = ConformanceSuiteClient(HOSTED_URL, token="tok")
    client.create_plan(
        "oidcc-client-basic-certification-test-plan",
        {"client_registration": "static_client"},
        "py-identity-model-basic-rp",
        publish="summary",
    )

    body = json.loads(route.calls.last.request.content)
    assert body["publish"] == "summary"


@respx.mock
def test_create_plan_defaults_publish_to_empty() -> None:
    route = respx.post(f"{HOSTED_URL}/api/plan").mock(
        return_value=httpx.Response(200, json={"id": "p1", "modules": []})
    )

    client = ConformanceSuiteClient(HOSTED_URL, token="tok")
    client.create_plan("plan", {}, "alias")

    body = json.loads(route.calls.last.request.content)
    assert body["publish"] == ""


# ---------------------------------------------------------------------------
# _should_download_package gate
# ---------------------------------------------------------------------------


def test_no_cert_package_path_means_no_download() -> None:
    do_download, reason = _should_download_package(None, HOSTED_URL, all_ok=True)
    assert do_download is False
    assert reason is None


def test_local_suite_skips_download() -> None:
    do_download, reason = _should_download_package("out.zip", LOCAL_URL, all_ok=True)
    assert do_download is False
    assert reason is not None
    assert "local suite" in reason


def test_failed_run_skips_download() -> None:
    do_download, reason = _should_download_package("out.zip", HOSTED_URL, all_ok=False)
    assert do_download is False
    assert reason == "not all tests passed"


def test_hosted_passing_run_downloads() -> None:
    do_download, reason = _should_download_package("out.zip", HOSTED_URL, all_ok=True)
    assert do_download is True
    assert reason is None
