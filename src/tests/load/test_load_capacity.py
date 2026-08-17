"""Real-Locust capacity/breakpoint proof for the load suite — TH-4.

This is the capacity ``test``-phase DoD: a REAL open-model ramp (Locust paced
via ``constant_throughput``) driving the booted RS (real uvicorn subprocess,
real HTTP) up the arrival-rate ladder until goodput stops tracking offered load
— the knee. A green fixed-load run is not proof of a capacity limit; this drives
load to saturation and records where the single worker falls over.

The knee is a *co-located, directional* ceiling (generator + mock OP + RS share
the box, per the design's accepted trade-off) plus a regression signal — NOT the
RS's absolute isolated limit, which needs a deployed target. The assertions here
pin the *mechanism* (a breakpoint is found, goodput plateaus, zero 5xx under
saturation), never a machine-specific RPS number.

Self-contained and skips cleanly without the load group (see the CI-short suite
for why locust must not be imported in-process). Run via
``make test-harness-load-capacity`` under ``uv run --group load --all-packages``.
"""

from __future__ import annotations

import importlib.util
import os

import pytest


if importlib.util.find_spec("locust") is None:
    pytest.skip("locust (load group) not installed", allow_module_level=True)
pytest.importorskip("fastapi_identity_model")
pytest.importorskip("uvicorn")

from ..load.runner import (
    render_capacity_report,
    run_capacity_profile,
    write_capacity_report,
)
from ..load.scenarios import Profile, profile_scenarios


pytestmark = pytest.mark.integration

_CAPACITY_IDS = [s.id for s in profile_scenarios(Profile.CAPACITY)]

# Where the fixture writes the rendered ramp curve + knee so CI can upload it as
# an artifact. Defaults to the repo/cwd so a local run also leaves a readable
# report (gitignored); the nightly job overrides it to the artifact path.
_REPORT_PATH = os.environ.get("HARNESS_CAPACITY_REPORT", "capacity-report.txt")


@pytest.fixture(scope="module")
def capacity_results():
    """Run the CAPACITY profile once; share the per-scenario ramp results.

    Each ramp boots its own RS and stops at the first rung that breaches SLO, so
    a saturating single worker knees within a few rungs — bounded run time. The
    rendered report is written to ``_REPORT_PATH`` before the assertions run, so
    the downloadable artifact exists even when a later assertion fails.
    """
    results = {r.scenario_id: r for r in run_capacity_profile(Profile.CAPACITY)}
    write_capacity_report(list(results.values()), _REPORT_PATH)
    return results


def test_every_capacity_scenario_ran(capacity_results):
    """The profile executed exactly the capacity catalogue (C1, C2)."""
    assert set(capacity_results) == set(_CAPACITY_IDS)


def test_each_ramp_found_a_breakpoint(capacity_results):
    """Every ramp reached the knee inside its ladder (not exhausted clean).

    ``found_breakpoint`` false would mean ``stop_rps`` was too low to saturate
    the worker — a mis-calibrated ladder, not a passing run.
    """
    for scenario_id, r in capacity_results.items():
        assert r.found_breakpoint, (
            f"{scenario_id}: ramp exhausted the ladder without a breakpoint "
            f"(top rung sustained); raise stop_rps. Curve:\n"
            f"{render_capacity_report([r])}"
        )
        assert r.breaking_target_rps is not None
        assert r.max_sustainable_rps > 0, f"{scenario_id}: could not sustain rung 1"
        assert r.knee_target_rps < r.breaking_target_rps


def test_knee_is_a_goodput_plateau(capacity_results):
    """The breaking rung is a real saturation: achieved goodput fell below the
    offered rate, and a breach reason was recorded (not a spurious stop)."""
    for scenario_id, r in capacity_results.items():
        breaking = r.steps[-1]
        assert breaking.breached
        assert breaking.reasons
        assert breaking.achieved_rps < r.breaking_target_rps, (
            f"{scenario_id}: breaking rung {r.breaking_target_rps} achieved "
            f"{breaking.achieved_rps:.0f} rps — expected goodput below offered"
        )


def test_no_server_errors_under_saturation(capacity_results):
    """Even driven past its knee the RS must never 5xx — it rejects/serves
    cleanly under overload, it does not fault (design §5 correctness invariant)."""
    for scenario_id, r in capacity_results.items():
        offenders = [s for s in r.steps if s.server_errors]
        assert not offenders, (
            f"{scenario_id}: 5xx under load at rungs "
            f"{[(s.target_rps, s.server_errors) for s in offenders]}"
        )


def test_offered_rate_is_monotonic(capacity_results):
    """The ladder offered a strictly increasing arrival rate."""
    for scenario_id, r in capacity_results.items():
        targets = [s.target_rps for s in r.steps]
        assert targets == sorted(set(targets)), f"{scenario_id}: {targets}"


def test_sustained_rungs_tracked_the_offered_rate(capacity_results):
    """Every non-breaching rung delivered >= sustain_ratio of what it offered —
    the invariant that makes the last sustained rung a trustworthy knee."""
    ramps = {
        s.id: s.ramp for s in profile_scenarios(Profile.CAPACITY) if s.ramp is not None
    }
    for scenario_id, r in capacity_results.items():
        ratio = ramps[scenario_id].sustain_ratio
        for step in r.steps:
            if not step.breached:
                assert step.achieved_rps >= ratio * step.target_rps


def test_capacity_report_renders_a_knee(capacity_results):
    """The artifact report names each scenario and its knee."""
    report = render_capacity_report(list(capacity_results.values()))
    for scenario_id in capacity_results:
        assert scenario_id in report
    assert "KNEE" in report
