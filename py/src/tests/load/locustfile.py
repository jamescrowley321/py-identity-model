"""Standalone Locust file replaying the pre-minted pool against the booted RS.

Run as a **subprocess** (``locust --headless -f locustfile.py``) by :mod:`runner`,
NOT imported in-process: locust imports trigger gevent's ``monkey.patch_all()``,
which deadlocks the parent's in-process asyncio mock-OP server thread. Isolating
Locust in its own process keeps gevent's patched world away from the mock OP
(served in the parent) and the RS (a separate uvicorn subprocess).

The parent hands two file paths through the environment:

* ``HARNESS_POOL_FILE`` — a JSON array of ``{"name", "token", "expected_status"}``
  entries (the pre-minted replay pool).
* ``HARNESS_RESULT_FILE`` — where this file writes the run summary on quit:
  aggregate RPS + p50/p95/p99/p999 latency, the 5xx count the parent asserts is
  zero, and a per-class breakdown carrying each class's request/failure counts
  **and** its p50/p95/p99 latency (so the S2 RS256-vs-ES256 cost ratio is
  computable from the result).

A response is scored a *failure* only when its status diverges from the class's
``expected_status`` — expected 401/403 rejections are the correct outcome and stay
out of the error budget (design §5 error-rate-by-class).

``locust``/``gevent`` resolve only under ``uv run --group load``; this module is
pyrefly-excluded in the root lint env for that reason.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
from typing import Any

from locust import HttpUser, constant_throughput, events, task


HTTP_SERVER_ERROR_FLOOR = 500

_POOL: list[dict[str, Any]] = json.loads(
    Path(os.environ["HARNESS_POOL_FILE"]).read_text()
)
if not _POOL:
    raise ValueError("HARNESS_POOL_FILE described an empty replay pool")

# Open-model pacing (TH-4 capacity ramp). When the runner sets a per-user target
# throughput (req/s), each user is paced to it via ``constant_throughput`` so the
# process offers a controlled arrival rate (users x rate) and the goodput knee is
# visible. Unset/0 keeps the fixed-hold *closed-loop* generator (no wait_time),
# so the existing S1-S12 scenarios are byte-for-byte unchanged.
_THROUGHPUT_PER_USER = float(os.environ.get("HARNESS_THROUGHPUT_PER_USER", "") or 0.0)

# Server-error (5xx) tally — a real defect the parent asserts is zero (design §5).
# A one-element list (not a bare ``int`` + ``global``) so the event listener can
# mutate it without a module-level ``global`` statement.
_server_errors = [0]


class ReplayUser(HttpUser):
    """Replays a random pooled token at ``/protected`` every task.

    Closed-loop by default (no ``wait_time`` → fire back-to-back). When the
    runner requests an open-model ramp (``HARNESS_THROUGHPUT_PER_USER`` > 0) each
    user is paced to that rate so the offered arrival rate is controlled.
    """

    if _THROUGHPUT_PER_USER > 0:
        wait_time = constant_throughput(_THROUGHPUT_PER_USER)

    @task
    def hit_protected(self) -> None:
        entry = secrets.choice(_POOL)
        with self.client.get(
            "/protected",
            headers={"Authorization": f"Bearer {entry['token']}"},
            name=entry["name"],
            catch_response=True,
        ) as response:
            if response.status_code == entry["expected_status"]:
                response.success()
            else:
                response.failure(
                    f"{entry['name']}: expected {entry['expected_status']}, "
                    f"got {response.status_code}"
                )


@events.request.add_listener
def _count_server_errors(response: Any = None, **_kw: Any) -> None:
    status = getattr(response, "status_code", None)
    if status is not None and status >= HTTP_SERVER_ERROR_FLOOR:
        _server_errors[0] += 1


@events.quitting.add_listener
def _write_summary(environment: Any, **_kw: Any) -> None:
    """Serialise the run summary for the parent runner to read back."""
    total = environment.stats.total
    by_class: dict[str, dict[str, float]] = {}
    for (name, _method), entry in environment.stats.entries.items():
        # Per-class latency percentiles (not just counts) so the parent can
        # compute the S2 alg-cost ratio (ES256 vs RS256) from the summary.
        by_class[name] = {
            "requests": entry.num_requests,
            "failures": entry.num_failures,
            "p50": float(entry.get_response_time_percentile(0.5)),
            "p95": float(entry.get_response_time_percentile(0.95)),
            "p99": float(entry.get_response_time_percentile(0.99)),
        }
    summary = {
        "num_requests": total.num_requests,
        "num_failures": total.num_failures,
        "rps": float(getattr(total, "total_rps", 0.0)),
        "p50": float(total.get_response_time_percentile(0.5)),
        "p95": float(total.get_response_time_percentile(0.95)),
        "p99": float(total.get_response_time_percentile(0.99)),
        "p999": float(total.get_response_time_percentile(0.999)),
        "server_errors": _server_errors[0],
        "by_class": by_class,
    }
    Path(os.environ["HARNESS_RESULT_FILE"]).write_text(json.dumps(summary))
