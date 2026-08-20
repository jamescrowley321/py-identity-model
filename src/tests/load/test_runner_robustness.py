"""Deterministic unit coverage for the runner's degenerate-window de-flake — TH-4.

`run_scenario` re-drives a steady-state scenario once when its first Locust window
recorded ~zero requests — a cold-runner startup flake (gevent patch + import +
connect ate the short window), not a real measurement. These tests pin the pure
decision (`_degenerate_window`) that gates the re-drive, without booting Locust.
"""

from __future__ import annotations

import pytest

from ..load import runner
from ..load.scenarios import SCENARIOS_BY_ID


pytestmark = pytest.mark.unit


def test_steady_state_zero_requests_is_degenerate() -> None:
    """A steady-state window that drove no requests must be re-driven."""
    s1 = SCENARIOS_BY_ID["S1"]  # steady_state=True
    assert runner._degenerate_window(s1, {"num_requests": 0}) is True


def test_steady_state_with_requests_is_not_degenerate() -> None:
    """A window that actually drove load is a real measurement — no re-drive."""
    s1 = SCENARIOS_BY_ID["S1"]
    assert runner._degenerate_window(s1, {"num_requests": 1000}) is False
    assert runner._degenerate_window(s1, {"num_requests": 1}) is False


def test_failure_injection_zero_requests_is_not_degenerate() -> None:
    """A failure-injection scenario (steady_state=False) can legitimately drive
    few requests — a low count there is signal, not a flake, so never re-driven."""
    s6 = SCENARIOS_BY_ID["S6"]  # kid-rotation storm, steady_state=False
    assert s6.steady_state is False
    assert runner._degenerate_window(s6, {"num_requests": 0}) is False


def test_missing_num_requests_is_degenerate_for_steady_state() -> None:
    """A summary with no num_requests key is treated as zero (defensive)."""
    s1 = SCENARIOS_BY_ID["S1"]
    assert runner._degenerate_window(s1, {}) is True
