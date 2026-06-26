"""Tests for plan-export download in conformance/run_tests.py.

These cover the pieces that let a hosted run capture evidence artifacts:

- ``ConformanceSuiteClient.download_plan_export`` — the read-only REST call that
  downloads the signed plan export zip (``GET /api/plan/{kind}/{plan_id}``).
- ``ConformanceSuiteClient.create_plan`` honouring the ``publish`` setting.
- ``_should_download_export`` — the gate deciding when an export is worth
  keeping (hosted suite + all tests passed only).

The export is deliberately distinct from the OIDF *certification package* (a
manual, publish-and-freeze ``POST .../certificationpackage`` step requiring a
signed PDF), which is not exercised here.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from run_tests import (
    ConformanceSuiteClient,
    _parse_content_disposition_filename,
    _should_download_export,
    print_summary,
)
from run_tests import TestResult as _TestResult  # aliased: avoid pytest collection


HOSTED_URL = "https://www.certification.openid.net"
LOCAL_URL = "https://localhost.emobix.co.uk:8443"

# Minimal valid zip magic — download_plan_export rejects non-zip payloads.
ZIP_MAGIC = b"PK\x03\x04"


# ---------------------------------------------------------------------------
# download_plan_export
# ---------------------------------------------------------------------------


@respx.mock
def test_download_plan_export_returns_filename_and_bytes() -> None:
    plan_id = "abc123"
    zip_bytes = ZIP_MAGIC + b" fake-export-payload"
    route = respx.get(f"{HOSTED_URL}/api/plan/export/{plan_id}").mock(
        return_value=httpx.Response(
            200,
            content=zip_bytes,
            headers={"content-disposition": 'attachment; filename="plan-abc123.zip"'},
        )
    )

    client = ConformanceSuiteClient(HOSTED_URL, token="tok-123")
    filename, content = client.download_plan_export(plan_id)

    assert content == zip_bytes
    assert filename == "plan-abc123.zip"
    assert route.called


@respx.mock
def test_download_plan_export_uses_kind_in_path() -> None:
    plan_id = "p1"
    route = respx.get(f"{HOSTED_URL}/api/plan/exporthtml/{plan_id}").mock(
        return_value=httpx.Response(200, content=ZIP_MAGIC + b"zip")
    )

    client = ConformanceSuiteClient(HOSTED_URL, token="tok")
    client.download_plan_export(plan_id, kind="exporthtml")

    assert route.called


@respx.mock
def test_download_plan_export_falls_back_when_no_disposition() -> None:
    plan_id = "noheader"
    respx.get(f"{HOSTED_URL}/api/plan/export/{plan_id}").mock(
        return_value=httpx.Response(200, content=ZIP_MAGIC + b"zip")
    )

    client = ConformanceSuiteClient(HOSTED_URL, token="tok")
    filename, _ = client.download_plan_export(plan_id)

    assert filename == "noheader-export.zip"


@respx.mock
def test_download_plan_export_no_over_capture_on_multiparam() -> None:
    # The old greedy regex (filename="(.+)") would swallow trailing parameters;
    # the quoted value must be parsed exactly.
    plan_id = "pmulti"
    respx.get(f"{HOSTED_URL}/api/plan/export/{plan_id}").mock(
        return_value=httpx.Response(
            200,
            content=ZIP_MAGIC + b"zip",
            headers={
                "content-disposition": 'attachment; filename="real.zip"; foo="bar"'
            },
        )
    )

    client = ConformanceSuiteClient(HOSTED_URL, token="tok")
    filename, _ = client.download_plan_export(plan_id)

    assert filename == "real.zip"


@respx.mock
def test_download_plan_export_rejects_non_zip_payload() -> None:
    # A 200 carrying an HTML proxy-error page must not be written as evidence.
    plan_id = "htmlerror"
    respx.get(f"{HOSTED_URL}/api/plan/export/{plan_id}").mock(
        return_value=httpx.Response(200, content=b"<html>502 Bad Gateway</html>")
    )

    client = ConformanceSuiteClient(HOSTED_URL, token="tok")
    with pytest.raises(ValueError, match="not a zip"):
        client.download_plan_export(plan_id)


@respx.mock
def test_download_plan_export_rejects_empty_payload() -> None:
    plan_id = "empty"
    respx.get(f"{HOSTED_URL}/api/plan/export/{plan_id}").mock(
        return_value=httpx.Response(200, content=b"")
    )

    client = ConformanceSuiteClient(HOSTED_URL, token="tok")
    with pytest.raises(ValueError, match="not a zip"):
        client.download_plan_export(plan_id)


@respx.mock
def test_download_plan_export_sends_bearer_token() -> None:
    plan_id = "plan-xyz"
    route = respx.get(f"{HOSTED_URL}/api/plan/export/{plan_id}").mock(
        return_value=httpx.Response(200, content=ZIP_MAGIC + b"zip")
    )

    client = ConformanceSuiteClient(HOSTED_URL, token="secret-token")
    client.download_plan_export(plan_id)

    assert route.calls.last.request.headers["Authorization"] == "Bearer secret-token"


@respx.mock
def test_download_plan_export_raises_on_error_status() -> None:
    plan_id = "missing"
    respx.get(f"{HOSTED_URL}/api/plan/export/{plan_id}").mock(
        return_value=httpx.Response(404)
    )

    client = ConformanceSuiteClient(HOSTED_URL, token="tok")
    with pytest.raises(httpx.HTTPStatusError) as exc_info:
        client.download_plan_export(plan_id)

    assert exc_info.value.response.status_code == httpx.codes.NOT_FOUND


# ---------------------------------------------------------------------------
# Content-Disposition filename parsing
# ---------------------------------------------------------------------------


def test_parse_content_disposition_quoted() -> None:
    assert (
        _parse_content_disposition_filename('attachment; filename="a b.zip"')
        == "a b.zip"
    )


def test_parse_content_disposition_extended_form() -> None:
    # RFC 5987 percent-encoded extended filename is decoded with its charset.
    disposition = "attachment; filename*=UTF-8''r%C3%A9el.zip"
    assert _parse_content_disposition_filename(disposition) == "réel.zip"


def test_parse_content_disposition_no_over_capture() -> None:
    disposition = 'attachment; filename="real.zip"; foo="bar"'
    assert _parse_content_disposition_filename(disposition) == "real.zip"


def test_parse_content_disposition_absent_returns_none() -> None:
    assert _parse_content_disposition_filename("attachment") is None
    assert _parse_content_disposition_filename("") is None


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
# _should_download_export gate
# ---------------------------------------------------------------------------


def test_no_export_path_means_no_download() -> None:
    do_download, reason = _should_download_export(None, HOSTED_URL, all_ok=True)
    assert do_download is False
    assert reason is None


def test_local_suite_skips_download() -> None:
    do_download, reason = _should_download_export("out.zip", LOCAL_URL, all_ok=True)
    assert do_download is False
    assert reason is not None
    assert "local suite" in reason


def test_failed_run_skips_download() -> None:
    do_download, reason = _should_download_export("out.zip", HOSTED_URL, all_ok=False)
    assert do_download is False
    assert reason == "not all tests passed"


def test_hosted_passing_run_downloads() -> None:
    do_download, reason = _should_download_export("out.zip", HOSTED_URL, all_ok=True)
    assert do_download is True
    assert reason is None


# ---------------------------------------------------------------------------
# print_summary evidence gate (drives all_ok → export gating + exit code)
# ---------------------------------------------------------------------------


def _result(status: str) -> _TestResult:
    return _TestResult(test_name=f"t-{status}", test_id="id", status=status)


def test_summary_empty_run_is_not_passing() -> None:
    # "nothing ran" must not count as all-passed evidence.
    assert print_summary([]) is False


def test_summary_all_passing_statuses_pass() -> None:
    results = [_result("PASSED"), _result("WARNING"), _result("SKIPPED")]
    assert print_summary(results) is True


def test_summary_review_status_blocks_pass() -> None:
    # REVIEW needs a human — it must not gate an export open.
    results = [_result("PASSED"), _result("REVIEW")]
    assert print_summary(results) is False


def test_summary_failed_status_blocks_pass() -> None:
    results = [_result("PASSED"), _result("FAILED")]
    assert print_summary(results) is False


def test_summary_unknown_status_blocks_pass() -> None:
    results = [_result("PASSED"), _result("WEIRD")]
    assert print_summary(results) is False
