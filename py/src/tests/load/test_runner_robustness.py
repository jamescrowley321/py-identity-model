"""Deterministic unit coverage for the runner's degenerate-window de-flake — TH-4.

`run_scenario` re-drives a scenario once when its first Locust window recorded
~zero requests — a cold-runner startup flake (gevent patch + import + connect ate
the short window), not a real measurement. These tests pin the pure decision
(`_degenerate_window`) that gates the re-drive, without booting Locust.
"""

from __future__ import annotations

import pytest

from ..load import runner


pytestmark = pytest.mark.unit


def test_zero_requests_is_degenerate() -> None:
    """A window that drove no requests must be re-driven."""
    assert runner._degenerate_window({"num_requests": 0}) is True


def test_missing_num_requests_is_degenerate() -> None:
    """A summary with no num_requests key is treated as zero (defensive)."""
    assert runner._degenerate_window({}) is True


def test_any_requests_is_not_degenerate() -> None:
    """A window that actually drove load — even a single request — is a real
    measurement, so it is never re-driven and its data is never masked."""
    assert runner._degenerate_window({"num_requests": 1}) is False
    assert runner._degenerate_window({"num_requests": 1000}) is False


def test_decision_is_scenario_independent() -> None:
    """The re-drive keys on the request count alone, not the scenario type: a fast
    failure-injection scenario (S6, steady_state=False, in the PR gate) that
    recorded zero requests is the same startup flake as a steady-state one, so it
    must be re-driven too — the earlier steady_state-only exemption left S6
    exposed to the exact flake this de-flake fixes.
    """
    # _degenerate_window takes only the summary — there is no scenario-type branch
    # left to exempt S6 (or any other zero-request window).
    assert runner._degenerate_window({"num_requests": 0}) is True
