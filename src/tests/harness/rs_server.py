"""Boot the harness resource server (:mod:`rs_app`) under real uvicorn workers.

``boot_rs`` is deliberately free of any FastAPI / fastapi-identity-model import
so it stays inside the root pyrefly lint env. It launches uvicorn as a
subprocess by import-string (``src.tests.harness.rs_app:app``), passes RS
configuration through inherited ``RS_*`` environment variables, waits for the
``/health`` endpoint to answer over real HTTP, then tears the process down.
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from typing import TYPE_CHECKING

import httpx


if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping


# src/tests/harness/rs_server.py -> parents[3] is the repo root (holds ``src/``).
_REPO_ROOT = Path(__file__).resolve().parents[3]

_HEALTH_POLL_INTERVAL = 0.25
_TERMINATE_GRACE = 10.0


def _free_port() -> int:
    """Bind to an ephemeral port, then release it for uvicorn to reuse.

    A TOCTOU window exists between close and re-bind; the ``/health`` readiness
    poll (which fails loudly if uvicorn never binds) is the real guard.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _drain(proc: subprocess.Popen[str]) -> str:
    return proc.stdout.read() if proc.stdout is not None else ""


def _wait_for_health(
    proc: subprocess.Popen[str], base_url: str, timeout: float
) -> None:
    deadline = time.monotonic() + timeout
    last_error = "no attempt made"
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(
                f"uvicorn exited before becoming healthy "
                f"(code {proc.returncode}):\n{_drain(proc)}"
            )
        try:
            response = httpx.get(f"{base_url}/health", timeout=2.0)
            if response.status_code == httpx.codes.OK:
                return
            last_error = f"HTTP {response.status_code}"
        except httpx.HTTPError as exc:
            last_error = str(exc)
        time.sleep(_HEALTH_POLL_INTERVAL)

    proc.terminate()
    raise RuntimeError(
        f"resource server did not become healthy within {timeout}s "
        f"(last: {last_error}):\n{_drain(proc)}"
    )


@contextlib.contextmanager
def boot_rs(  # noqa: PLR0913 — each RS knob (issuer/audience/scope/workers/...) is an explicit keyword
    *,
    discovery_url: str,
    audience: str,
    require_scope: str = "api",
    workers: int = 1,
    require_access_token_marker: bool = False,
    excluded_paths: list[str] | None = None,
    extra_env: Mapping[str, str] | None = None,
    timeout: float = 30.0,
) -> Iterator[str]:
    """Boot a single-issuer resource server and yield its base URL.

    Args:
        discovery_url: OIDC discovery URL the middleware binds to.
        audience: Expected ``aud`` claim (middleware requires non-empty).
        require_scope: Scope enforced on ``/protected`` (403 if absent).
        workers: uvicorn ``--workers`` count (>=2 proves multi-worker boot).
        require_access_token_marker: F-07 ID-token-substitution defence opt-in.
        excluded_paths: Override middleware excluded paths (must keep
            ``/health`` for the readiness poll to pass).
        extra_env: Additional environment for the uvicorn subprocess.
        timeout: Seconds to wait for the first healthy ``/health`` response.

    Yields:
        The ``http://127.0.0.1:<port>`` base URL of the running server.
    """
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"

    env = dict(os.environ)
    env["RS_DISCOVERY_URL"] = discovery_url
    env["RS_AUDIENCE"] = audience
    env["RS_REQUIRE_SCOPE"] = require_scope
    env["RS_REQUIRE_ACCESS_TOKEN_MARKER"] = (
        "true" if require_access_token_marker else "false"
    )
    if excluded_paths is not None:
        env["RS_EXCLUDED_PATHS"] = ",".join(excluded_paths)
    if extra_env:
        env.update(extra_env)

    proc = subprocess.Popen(  # noqa: S603 — fixed argv, no shell, test-only
        [
            sys.executable,
            "-m",
            "uvicorn",
            "src.tests.harness.rs_app:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--workers",
            str(workers),
            "--log-level",
            "warning",
        ],
        cwd=str(_REPO_ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        _wait_for_health(proc, base_url, timeout)
        yield base_url
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=_TERMINATE_GRACE)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=_TERMINATE_GRACE)
        finally:
            # Close the inherited stdout pipe explicitly. Leaving it to the GC
            # raises ResourceWarning, which pytest's ``filterwarnings=error``
            # promotes to an unraisable-exception failure in a later test.
            if proc.stdout is not None:
                proc.stdout.close()
