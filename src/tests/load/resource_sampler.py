"""RS process-tree RSS/FD sampler for the soak scenarios — T313 (epic #462, §5).

The soak scenarios (S11 "RSS / FD soak", S12 multi-tenant, S4 TTL rollover) exist
to prove the middleware's caches are *bounded*: a long run against many issuers
must not leak memory (RSS) or file descriptors (JWKS/discovery connections). That
claim needs a measurement — this module samples the booted RS's process tree
while a scenario runs and reports the RSS/FD trend.

Why a *tree*, not one PID: :func:`~tests.harness.rs_server.boot_rs` launches
uvicorn with ``--workers N``, so the request handlers are child processes of the
master. Sampling the master alone misses the workers where the caches actually
live; :func:`sample_process_tree` sums the master and its recursive children.

Why *growth*, not an absolute ceiling: RSS/FD *deltas* over a fixed window are
machine-independent (a leak grows on any box), unlike an absolute RSS number that
depends on the interpreter build and page size. The co-located run therefore
yields a meaningful leak signal even though its absolute throughput is directional
(design §10).
"""

from __future__ import annotations

from dataclasses import dataclass
import threading

import psutil


_BYTES_PER_MB = 1024 * 1024
_DEFAULT_INTERVAL = 0.5  # seconds between samples


def sample_process_tree(pid: int) -> tuple[int, int]:
    """Return ``(rss_bytes, fd_count)`` summed over ``pid`` and its children.

    Sums the master and every recursive child so a multi-worker RS is measured
    whole. Processes that vanish mid-sample (a worker recycling) are skipped
    rather than raising — a transient tree change must not crash the sampler.
    ``fd_count`` is ``0`` on platforms without ``num_fds`` (e.g. Windows); CI and
    the dev box are Linux, where it reflects open descriptors.
    """
    try:
        master = psutil.Process(pid)
        procs = [master, *master.children(recursive=True)]
    except psutil.Error:
        return (0, 0)

    rss = 0
    fds = 0
    for proc in procs:
        try:
            rss += proc.memory_info().rss
            with _suppress_no_fd_support():
                fds += proc.num_fds()
        except psutil.Error:
            # NoSuchProcess/AccessDenied/ZombieProcess for one process in the
            # tree: skip it, keep summing the rest.
            continue
    return (rss, fds)


class _suppress_no_fd_support:
    """Swallow the ``AttributeError`` from ``num_fds`` on platforms lacking it."""

    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type: type[BaseException] | None, *_: object) -> bool:
        return exc_type is not None and issubclass(exc_type, AttributeError)


@dataclass(frozen=True)
class ResourceSample:
    """RSS/FD trend of an RS process tree across one scenario run.

    ``num_samples`` is ``0`` when nothing was sampled (the process was gone the
    whole window); callers treat that as "no data", not "zero growth".
    """

    rss_start_mb: float
    rss_max_mb: float
    rss_end_mb: float
    fd_start: int
    fd_max: int
    fd_end: int
    num_samples: int

    @property
    def rss_growth_mb(self) -> float:
        """Peak RSS minus the starting RSS — the memory-leak signal (MB)."""
        return self.rss_max_mb - self.rss_start_mb

    @property
    def fd_growth(self) -> int:
        """Peak FD count minus the starting count — the descriptor-leak signal."""
        return self.fd_max - self.fd_start

    @property
    def sampled(self) -> bool:
        """Whether the window captured at least one sample (data is meaningful)."""
        return self.num_samples > 0


_EMPTY_SAMPLE = ResourceSample(0.0, 0.0, 0.0, 0, 0, 0, 0)


class ResourceSampler:
    """Sample an RS process tree's RSS/FD on a background thread during a run.

    Use as a context manager around the load-driving call:

        with ResourceSampler(pid) as sampler:
            ... drive load ...
        sample = sampler.result

    The daemon thread ticks every ``interval`` seconds; the first tick is the
    baseline (``rss_start``/``fd_start``), the peak across the window is the max,
    and the last tick is the end. A tick that raises never propagates — the
    sampler must not fail a scenario. When ``pid`` never yields a live sample the
    result is the all-zero :data:`ResourceSample` with ``num_samples == 0``.
    """

    def __init__(self, pid: int, *, interval: float = _DEFAULT_INTERVAL) -> None:
        self._pid = pid
        self._interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._samples: list[tuple[int, int]] = []
        self.result: ResourceSample = _EMPTY_SAMPLE

    def _run(self) -> None:
        # Take an immediate baseline sample, then keep sampling until stopped so
        # even a sub-``interval`` run records at least the start reading.
        self._samples.append(sample_process_tree(self._pid))
        while not self._stop.wait(self._interval):
            self._samples.append(sample_process_tree(self._pid))

    def __enter__(self) -> ResourceSampler:
        self._thread = threading.Thread(
            target=self._run, name=f"rss-fd-sampler-{self._pid}", daemon=True
        )
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self._interval * 4)
        self.result = self._summarize()

    def _summarize(self) -> ResourceSample:
        # Only samples where the tree was actually alive (rss > 0) count; a run
        # whose process died leaves an all-zero sample => num_samples 0.
        live = [(rss, fds) for rss, fds in self._samples if rss > 0]
        if not live:
            return _EMPTY_SAMPLE
        rss_vals = [rss for rss, _ in live]
        fd_vals = [fds for _, fds in live]
        return ResourceSample(
            rss_start_mb=rss_vals[0] / _BYTES_PER_MB,
            rss_max_mb=max(rss_vals) / _BYTES_PER_MB,
            rss_end_mb=rss_vals[-1] / _BYTES_PER_MB,
            fd_start=fd_vals[0],
            fd_max=max(fd_vals),
            fd_end=fd_vals[-1],
            num_samples=len(live),
        )
