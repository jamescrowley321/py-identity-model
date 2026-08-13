"""Standalone Locust file replaying the pre-minted pool against the booted RS.

Run as a **subprocess** (``locust --headless -f locustfile.py``) by :mod:`runner`,
NOT imported in-process: locust imports trigger gevent's ``monkey.patch_all()``,
which deadlocks the parent's in-process asyncio mock-OP server thread. Isolating
Locust in its own process keeps gevent's patched world away from the mock OP
(served in the parent) and the RS (a separate uvicorn subprocess).

The parent hands two file paths through the environment:

* ``HARNESS_POOL_FILE`` — a JSON array of ``{"name", "token", "expected_status"}``
  entries (the pre-minted replay pool).
* ``HARNESS_RESULT_FILE`` — where this file writes the run summary on quit
  (per-class request/failure counts, latency percentiles, RPS, and the 5xx count
  the parent asserts is zero).

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

from locust import HttpUser, events, task


HTTP_SERVER_ERROR_FLOOR = 500

_POOL: list[dict[str, Any]] = json.loads(
    Path(os.environ["HARNESS_POOL_FILE"]).read_text()
)
if not _POOL:
    raise ValueError("HARNESS_POOL_FILE described an empty replay pool")

# Server-error (5xx) tally — a real defect the parent asserts is zero (design §5).
# A one-element list (not a bare ``int`` + ``global``) so the event listener can
# mutate it without a module-level ``global`` statement.
_server_errors = [0]


class ReplayUser(HttpUser):
    """Replays a random pooled token at ``/protected`` every task."""

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
    by_class: dict[str, dict[str, int]] = {}
    for (name, _method), entry in environment.stats.entries.items():
        by_class[name] = {
            "requests": entry.num_requests,
            "failures": entry.num_failures,
        }
    summary = {
        "num_requests": total.num_requests,
        "num_failures": total.num_failures,
        "rps": float(getattr(total, "total_rps", 0.0)),
        "p50": float(total.get_response_time_percentile(0.5)),
        "p95": float(total.get_response_time_percentile(0.95)),
        "p99": float(total.get_response_time_percentile(0.99)),
        "server_errors": _server_errors[0],
        "by_class": by_class,
    }
    Path(os.environ["HARNESS_RESULT_FILE"]).write_text(json.dumps(summary))
