"""Real-Locust nightly soak proof for the load suite — TH-1.5 (#271, epic #462).

The scheduled counterpart to :mod:`test_load_ci_short`. Runs the NIGHTLY scenario
profile (S4 TTL-rollover — needs a >60s window past the 60s cache-TTL floor — plus
the S7 LRU-thrash and S11/S12 RSS/FD soak scenarios) with the same real-Locust-vs-
booted-RS machinery, but the long-window work that does not belong on the PR gate.

Scheduled by ``.github/workflows/nightly.yml``; run on demand via
``make test-harness-load-nightly`` under ``uv run --group load --all-packages``.

Self-contained (the controllable mock OP is the failure-injection driver — no
external IdP). See :mod:`test_load_ci_short` for why locust is never imported in
this process (gevent ``monkey.patch_all`` would deadlock the in-process mock OP).
"""

from __future__ import annotations

import importlib.util

import pytest


if importlib.util.find_spec("locust") is None:
    pytest.skip("locust (load group) not installed", allow_module_level=True)
pytest.importorskip("fastapi_identity_model")
pytest.importorskip("uvicorn")

from ..load.runner import evaluate_gates, run_profile
from ..load.scenarios import Profile, profile_scenarios


pytestmark = pytest.mark.integration

_NIGHTLY_IDS = [s.id for s in profile_scenarios(Profile.NIGHTLY)]


@pytest.fixture(scope="module")
def nightly_results():
    """Run the NIGHTLY soak profile once; share the per-scenario results.

    Each scenario boots its own mock OP + RS. S4 alone runs past the 60s cache
    TTL, so this fixture takes minutes — module scope so it runs once.
    """
    return {result.scenario_id: result for result in run_profile(Profile.NIGHTLY)}


def test_every_nightly_scenario_ran(nightly_results):
    """The profile executed exactly the NIGHTLY soak catalogue (S4, S7, S11, S12)."""
    assert set(nightly_results) == set(_NIGHTLY_IDS)


@pytest.mark.parametrize("scenario_id", _NIGHTLY_IDS)
def test_soak_scenario_drove_load_and_met_gates(nightly_results, scenario_id):
    """Each soak scenario drove real requests and violated no SLO/correctness gate."""
    result = nightly_results[scenario_id]
    assert result.num_requests > 0, f"{scenario_id} drove no load"
    # p999 is a percentile so it must be >= p99 (a reverted/zeroed field fails here).
    assert result.p999_ms >= result.p99_ms, (result.p999_ms, result.p99_ms)
    violations = evaluate_gates(result)
    assert not violations, "; ".join(violations)


def test_no_server_errors_anywhere(nightly_results):
    """Design §5 hard invariant: ZERO 500s across the whole soak.

    Under a multi-minute soak this is the leak/exhaustion tripwire — a resource
    leak that eventually 500s (OOM, FD exhaustion, pool starvation) shows up here.
    """
    offenders = {
        sid: r.server_errors for sid, r in nightly_results.items() if r.server_errors
    }
    assert not offenders, f"server errors (5xx): {offenders}"
