"""Tests for per-test RP client-side log capture.

Covers both halves of the `clientSideData` feature:

- Harness side (`app.py`): the per-test log router writes each active test's
  records to `<RP_LOG_DIR>/<profile>/<test_name>.log`, sanitises names, and
  stays silent when no test is active.
- Runner side (`run_tests.py`): the directory reset + flat-zip helpers that
  assemble the per-profile RP-logs bundle, and the shared `RP_LOG_DIR` default.
"""

from __future__ import annotations

import logging
import zipfile

import app as harness_app
import pytest
from run_tests import _reset_dir, _rp_log_dir, _zip_directory


@pytest.fixture(autouse=True)
def _reset_active_test():
    """Keep the process-wide active-test pointer from leaking across tests.

    Tests poke ``_set_active_test`` directly; an early failure before a manual
    reset would otherwise route a later test's records to a stale file.
    """
    harness_app._set_active_test(None, None)
    yield
    harness_app._set_active_test(None, None)


# ---------------------------------------------------------------------------
# Harness: per-test log router (app.py)
# ---------------------------------------------------------------------------


def test_router_writes_active_test_log(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("RP_LOG_DIR", str(tmp_path))
    harness_app._set_active_test("basic-rp", "oidcc-client-test-invalid-iss")
    try:
        logging.getLogger("conformance-rp").error("REJECTED: bad iss")
    finally:
        harness_app._set_active_test(None, None)

    log_file = tmp_path / "basic-rp" / "oidcc-client-test-invalid-iss.log"
    assert log_file.exists()
    assert "REJECTED: bad iss" in log_file.read_text()


def test_router_silent_when_no_active_test(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("RP_LOG_DIR", str(tmp_path))
    harness_app._set_active_test(None, None)
    logging.getLogger("conformance-rp").error("must not be written anywhere")

    assert not list(tmp_path.rglob("*.log"))


def test_rp_log_path_sanitises_and_creates_dir(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("RP_LOG_DIR", str(tmp_path))
    base = tmp_path.resolve()
    path = harness_app._rp_log_path("basic/rp", "oidcc/../evil")

    # Path separators in either component are neutralised — no escaping the base.
    assert path.name == "oidcc_.._evil.log"
    assert path.parent == base / "basic_rp"
    assert base in path.parents
    assert path.parent.is_dir()


def test_rp_log_path_collapses_dot_only_components(tmp_path, monkeypatch) -> None:
    # A profile of ".." survives the character class (all dots) but must not be
    # allowed to walk out of the base — it collapses to the fallback segment.
    monkeypatch.setenv("RP_LOG_DIR", str(tmp_path))
    base = tmp_path.resolve()
    path = harness_app._rp_log_path("..", "..")

    assert path == base / "default" / "unknown.log"
    assert base in path.parents


def test_rp_log_path_router_drops_dot_only_without_writing_outside(
    tmp_path, monkeypatch
) -> None:
    # End-to-end: routing a record for a dot-only profile/test writes inside the
    # base (collapsed), never a sibling of it.
    monkeypatch.setenv("RP_LOG_DIR", str(tmp_path / "base"))
    harness_app._set_active_test("..", "..")
    logging.getLogger("conformance-rp").error("REJECTED: dotty")

    assert not list((tmp_path).glob("*.log"))  # nothing beside the base
    written = list((tmp_path / "base").rglob("*.log"))
    assert [p.name for p in written] == ["unknown.log"]


def test_set_active_test_clears_on_empty_name() -> None:
    harness_app._set_active_test("basic-rp", "")
    assert harness_app._get_active_test() is None
    harness_app._set_active_test("basic-rp", "some-test")
    assert harness_app._get_active_test() == ("basic-rp", "some-test")
    harness_app._set_active_test(None, None)
    assert harness_app._get_active_test() is None


# ---------------------------------------------------------------------------
# Runner: bundle assembly (run_tests.py)
# ---------------------------------------------------------------------------


def test_zip_directory_zips_files_flat(tmp_path) -> None:
    src = tmp_path / "config-rp"
    src.mkdir()
    (src / "test-a.log").write_text("a")
    (src / "test-b.log").write_text("b")
    nested = src / "sub"
    nested.mkdir()
    (nested / "ignored.log").write_text("c")  # directories are not recursed

    out = tmp_path / "bundle.zip"
    count = _zip_directory(src, out)

    expected_files = ["test-a.log", "test-b.log"]
    assert count == len(expected_files)
    with zipfile.ZipFile(out) as zf:
        assert sorted(zf.namelist()) == expected_files


def test_zip_directory_empty_dir_writes_empty_zip(tmp_path) -> None:
    src = tmp_path / "empty"
    src.mkdir()
    out = tmp_path / "bundle.zip"

    assert _zip_directory(src, out) == 0
    with zipfile.ZipFile(out) as zf:
        assert zf.namelist() == []


def test_reset_dir_clears_existing_contents(tmp_path) -> None:
    d = tmp_path / "profile"
    d.mkdir()
    (d / "stale.log").write_text("old")

    _reset_dir(d)

    assert d.is_dir()
    assert list(d.iterdir()) == []


def test_reset_dir_creates_when_absent(tmp_path) -> None:
    d = tmp_path / "missing" / "profile"
    _reset_dir(d)
    assert d.is_dir()


def test_rp_log_dir_honours_env(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("RP_LOG_DIR", str(tmp_path))
    assert _rp_log_dir() == tmp_path


def test_rp_log_dir_default_is_absolute(monkeypatch) -> None:
    monkeypatch.delenv("RP_LOG_DIR", raising=False)
    assert _rp_log_dir().is_absolute()
