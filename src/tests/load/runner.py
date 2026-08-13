"""Load/soak runner — TH-1.5 (#474 · epic #462, design §4/§5).

Orchestrates one scenario end to end: serve the mock OP over real HTTP, boot the
resource server under uvicorn against it, build the pre-minted replay pool, drive
load with a **real Locust run**, then collect the metrics design §5 asks for:
RPS, p50/p95/p99, error-rate-by-class (expected rejections excluded), cache-hit
rate (RS ``/metrics`` at workers=1) and upstream fetches per issuer (the mock OP's
in-process ``stats``).

Locust runs in a **subprocess** (``locust --headless -f locustfile.py``) rather
than programmatically: importing locust triggers gevent's ``monkey.patch_all()``,
which deadlocks the parent's in-process asyncio mock-OP server thread. Keeping
Locust out-of-process isolates gevent's patched world — the parent stays a plain
asyncio/threading process. The pre-minted pool crosses the boundary as a JSON file
(tokens are just strings); the run summary comes back the same way.

Each scenario runs against a **fresh** mock OP + RS so caches start empty and no
failure-injection state bleeds across scenarios.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import TYPE_CHECKING

import httpx

from ..harness import serve_mock_op
from ..harness.corpus import CORPUS_AUDIENCE
from ..harness.rs_server import boot_rs
from .pool import build_load_pool
from .scenarios import SCENARIOS_BY_ID, Profile, Scenario, profile_scenarios


if TYPE_CHECKING:
    from collections.abc import Iterator

    from ..harness.mock_op import MockOP
    from .pool import LoadPool


HTTP_SERVER_ERROR_FLOOR = 500
_LOCUSTFILE = Path(__file__).with_name("locustfile.py")
_LOCUST_GRACE = 60.0  # seconds of headroom over a scenario's run-time


@dataclass(frozen=True)
class Gate:
    """SLO thresholds for a scenario class (design §5).

    All fields start ``None`` (permissive) so a baseline run never fails on an
    uncalibrated threshold; the ``test`` phase measures and the ``docs`` phase
    writes the calibrated numbers here / into the README table.
    """

    max_p99_ms: float | None = None
    min_rps: float | None = None
    max_error_rate: float | None = None
    min_cache_hit_rate: float | None = None


# Gate key -> thresholds. Permissive until the test-phase baseline calibrates them.
GATES: dict[str, Gate] = {
    "warm": Gate(),
    "cold": Gate(),
}


@dataclass
class LoadResult:
    """The measured outcome of one scenario run."""

    scenario_id: str
    title: str
    num_requests: int
    num_failures: int
    rps: float
    p50_ms: float
    p95_ms: float
    p99_ms: float
    server_errors: int
    steady_state: bool
    requests_by_class: dict[str, int] = field(default_factory=dict)
    failures_by_class: dict[str, int] = field(default_factory=dict)
    cache_metrics: dict[str, int] = field(default_factory=dict)
    upstream_stats: dict[str, int] = field(default_factory=dict)

    @property
    def error_rate(self) -> float:
        """Unexpected-status fraction (expected 401/403 rejections excluded)."""
        return self.num_failures / self.num_requests if self.num_requests else 0.0

    @property
    def cache_hit_rate(self) -> float:
        """Combined discovery+JWKS hit rate over the measured window (0..1)."""
        m = self.cache_metrics
        hits = m.get("disco_hits", 0) + m.get("jwks_hits", 0)
        misses = m.get("disco_misses", 0) + m.get("jwks_misses", 0)
        total = hits + misses
        return hits / total if total else 1.0


def _scrape_cache_metrics(base_url: str) -> dict[str, int]:
    try:
        resp = httpx.get(f"{base_url}/metrics", timeout=5.0)
        resp.raise_for_status()
        return {k: int(v) for k, v in resp.json().items()}
    except (httpx.HTTPError, ValueError):  # pragma: no cover - defensive
        return {}


def _warm_cache(base_url: str, token: str) -> None:
    """Prime the RS discovery+JWKS cache before a warm-scenario measurement."""
    with contextlib.suppress(httpx.HTTPError):
        httpx.get(
            f"{base_url}/protected",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10.0,
        )


def _run_locust(base_url: str, pool: LoadPool, scenario: Scenario) -> dict:
    """Drive a real Locust run in a subprocess; return its summary dict."""
    with tempfile.TemporaryDirectory() as tmp:
        pool_file = Path(tmp) / "pool.json"
        result_file = Path(tmp) / "result.json"
        pool_file.write_text(
            json.dumps(
                [
                    {
                        "name": e.name,
                        "token": e.token,
                        "expected_status": e.expected_status,
                    }
                    for e in pool.entries
                ]
            )
        )
        run_seconds = max(1, int(scenario.duration_seconds))
        cmd = [
            sys.executable,
            "-m",
            "locust",
            "--headless",
            "-f",
            str(_LOCUSTFILE),
            "-u",
            str(scenario.users),
            "-r",
            str(scenario.users),  # ramp all users in one second
            "-t",
            f"{run_seconds}s",
            "--host",
            base_url,
            "--loglevel",
            "WARNING",
            # Expected 401/403 rejections are scored as successes, but a
            # failure-injection scenario legitimately produces failures; let the
            # parent evaluate gates from the summary rather than the exit code.
            "--exit-code-on-error",
            "0",
        ]
        env = {
            "HARNESS_POOL_FILE": str(pool_file),
            "HARNESS_RESULT_FILE": str(result_file),
        }
        completed = subprocess.run(  # noqa: S603 — fixed argv, no shell, test-only
            cmd,
            env={**os.environ, **env},
            capture_output=True,
            text=True,
            timeout=run_seconds + _LOCUST_GRACE,
            check=False,
        )
        if not result_file.exists():
            raise RuntimeError(
                f"locust produced no summary for {scenario.id} "
                f"(exit {completed.returncode}):\n{completed.stderr[-2000:]}"
            )
        return json.loads(result_file.read_text())


def run_scenario(scenario: Scenario, op: MockOP, base_url: str) -> LoadResult:
    """Drive one scenario against an already-booted RS and mock OP."""
    pool = build_load_pool(op, scenario.classes)

    # A warm scenario measures the hot-cache steady state: prime the cache with a
    # valid token, then zero the upstream counters so the measured window starts
    # clean. A cold scenario skips the warmup so its stampede fetches are counted.
    if scenario.gate == "warm":
        valid = next((e for e in pool.entries if e.name.startswith("valid")), None)
        if valid is not None:
            _warm_cache(base_url, valid.token)
    # Apply failure injection AFTER the pool is minted (valid tokens signed by the
    # published key) and after any warmup.
    if scenario.setup is not None:
        scenario.setup(op)
    op.stats.reset()

    summary = _run_locust(base_url, pool, scenario)
    return _to_result(scenario, summary, base_url, op)


def _to_result(
    scenario: Scenario, summary: dict, base_url: str, op: MockOP
) -> LoadResult:
    by_class = summary.get("by_class", {})
    return LoadResult(
        scenario_id=scenario.id,
        title=scenario.title,
        num_requests=int(summary.get("num_requests", 0)),
        num_failures=int(summary.get("num_failures", 0)),
        rps=float(summary.get("rps", 0.0)),
        p50_ms=float(summary.get("p50", 0.0)),
        p95_ms=float(summary.get("p95", 0.0)),
        p99_ms=float(summary.get("p99", 0.0)),
        server_errors=int(summary.get("server_errors", 0)),
        steady_state=scenario.steady_state,
        requests_by_class={n: v["requests"] for n, v in by_class.items()},
        failures_by_class={
            n: v["failures"] for n, v in by_class.items() if v["failures"]
        },
        cache_metrics=_scrape_cache_metrics(base_url),
        upstream_stats=op.stats.snapshot(),
    )


def evaluate_gates(result: LoadResult) -> list[str]:
    """Return SLO/correctness violations for a result (empty = passed).

    Two invariants hold regardless of threshold calibration: a scenario must emit
    ZERO server errors (500s — a real defect, design §5), and a *steady-state*
    scenario must have ZERO unexpected-status divergences (every class returned
    its expected 200/401/403). Perf thresholds are checked only once calibrated.
    """
    violations: list[str] = []
    if result.server_errors:
        violations.append(
            f"{result.scenario_id}: {result.server_errors} server error(s) "
            f"(>= {HTTP_SERVER_ERROR_FLOOR}) — must be 0"
        )
    if result.steady_state and result.num_failures:
        violations.append(
            f"{result.scenario_id}: {result.num_failures} unexpected status "
            f"divergence(s) under steady state ({result.failures_by_class})"
        )
    gate = GATES.get(_gate_key(result.scenario_id))
    if gate is not None:
        if gate.max_p99_ms is not None and result.p99_ms > gate.max_p99_ms:
            violations.append(
                f"{result.scenario_id}: p99 {result.p99_ms}ms > {gate.max_p99_ms}ms"
            )
        if gate.min_rps is not None and result.rps < gate.min_rps:
            violations.append(
                f"{result.scenario_id}: rps {result.rps:.1f} < {gate.min_rps}"
            )
        if gate.max_error_rate is not None and result.error_rate > gate.max_error_rate:
            violations.append(
                f"{result.scenario_id}: error-rate {result.error_rate:.4f} "
                f"> {gate.max_error_rate}"
            )
        if (
            gate.min_cache_hit_rate is not None
            and result.cache_hit_rate < gate.min_cache_hit_rate
        ):
            violations.append(
                f"{result.scenario_id}: cache-hit-rate {result.cache_hit_rate:.4f} "
                f"< {gate.min_cache_hit_rate}"
            )
    return violations


def _gate_key(scenario_id: str) -> str:
    scenario = SCENARIOS_BY_ID.get(scenario_id)
    return scenario.gate if scenario and scenario.gate else "warm"


def run_profile(profile: Profile) -> list[LoadResult]:
    """Run every scenario in *profile* against a fresh mock-OP-backed RS each.

    Each scenario gets its own in-process mock OP + booted RS so caches start
    empty and failure-injection state never bleeds across scenarios. The mock OP
    is the design's failure-injection driver (latency, 429, key rotation), so the
    self-contained CI_SHORT profile needs no external IdP — the node-oidc
    real-issuer leg (real minted tokens) is a separate test-phase concern.
    """
    results: list[LoadResult] = []
    for scenario in profile_scenarios(profile):
        with _scenario_stack() as (op, base_url):
            results.append(run_scenario(scenario, op, base_url))
    return results


@contextlib.contextmanager
def _scenario_stack() -> Iterator[tuple[MockOP, str]]:
    """Fresh mock OP + booted RS for a single scenario (clean cache each time)."""
    with (
        serve_mock_op() as op,
        boot_rs(
            discovery_url=op.discovery_url,
            audience=CORPUS_AUDIENCE,
            require_scope="read",
        ) as base_url,
    ):
        yield op, base_url
