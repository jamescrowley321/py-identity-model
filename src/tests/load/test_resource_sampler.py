"""Deterministic unit coverage for the soak RSS/FD sampler — T313 (epic #462).

Pure-logic tests over the sampler: the summarize math (start/max/end, dead-sample
filtering), the :class:`ResourceSample` leak-signal properties, live sampling of
this very process, and the not-sampled (dead-pid) path. No booted RS and no Locust
— the real soak sampling is exercised in ``test_load_nightly.py``. Marked ``unit``
so it runs in the coverage-gated suite (psutil is a ``dev`` dependency).
"""

from __future__ import annotations

import os

import pytest

from ..load.resource_sampler import (
    ResourceSample,
    ResourceSampler,
    sample_process_tree,
)
from ..load.runner import _maybe_sampler


pytestmark = pytest.mark.unit

_MB = 1024 * 1024


def test_resource_sample_growth_and_sampled_properties():
    """Growth deltas and ``sampled`` are derived from the recorded extremes."""
    sample = ResourceSample(
        rss_start_mb=100.0,
        rss_max_mb=175.0,
        rss_end_mb=140.0,
        fd_start=20,
        fd_max=27,
        fd_end=24,
        num_samples=6,
    )
    assert sample.rss_growth_mb == pytest.approx(75.0)
    assert sample.fd_growth == 7
    assert sample.sampled is True


def test_resource_sample_zero_samples_is_not_sampled():
    """A window that captured nothing reports ``sampled == False`` (no data)."""
    assert ResourceSample(0.0, 0.0, 0.0, 0, 0, 0, 0).sampled is False


def test_summarize_computes_start_max_end_and_drops_dead_samples():
    """Summarize uses the first/peak/last *live* readings; dead (rss==0) drop out.

    The leading and trailing ``(0, 0)`` readings (the tree not yet up / already
    torn down) must not become the start/end, or a real leak would be masked by a
    zero baseline.
    """
    sampler = ResourceSampler(pid=1234)
    sampler._samples = [
        (0, 0),  # tree not observed yet — must be filtered
        (100 * _MB, 30),
        (180 * _MB, 42),  # peak
        (150 * _MB, 38),
        (0, 0),  # torn down — must be filtered
    ]
    result = sampler._summarize()
    assert result.num_samples == 3
    assert result.rss_start_mb == pytest.approx(100.0)
    assert result.rss_max_mb == pytest.approx(180.0)
    assert result.rss_end_mb == pytest.approx(150.0)
    assert result.fd_start == 30
    assert result.fd_max == 42
    assert result.fd_end == 38
    assert result.rss_growth_mb == pytest.approx(80.0)
    assert result.fd_growth == 12


def test_summarize_all_dead_yields_empty_unsampled():
    """Every reading dead => the empty, un-sampled result (not a fake zero trend)."""
    sampler = ResourceSampler(pid=1234)
    sampler._samples = [(0, 0), (0, 0)]
    assert sampler._summarize().sampled is False


def test_sample_process_tree_live_process_reports_memory():
    """Sampling this test process's tree yields real RSS (and non-negative FDs)."""
    rss, fds = sample_process_tree(os.getpid())
    assert rss > 0
    assert fds >= 0


def test_sample_process_tree_dead_pid_is_zero():
    """A pid with no process yields ``(0, 0)`` rather than raising."""
    # PIDs are bounded by /proc/sys/kernel/pid_max; this one is above any real pid.
    assert sample_process_tree(2**31 - 1) == (0, 0)


def test_sampler_context_manager_captures_live_process():
    """The context manager samples the running process and reports a trend."""
    with ResourceSampler(os.getpid(), interval=0.02) as sampler:
        _ = [i * i for i in range(200_000)]
    result = sampler.result
    assert result.sampled is True
    assert result.num_samples >= 1
    assert result.rss_max_mb > 0
    assert result.rss_growth_mb >= 0


def test_sampler_context_manager_dead_pid_is_unsampled():
    """A dead pid over the whole window produces the un-sampled empty result."""
    with ResourceSampler(2**31 - 1, interval=0.01) as sampler:
        pass
    assert sampler.result.sampled is False


def test_maybe_sampler_none_pid_yields_none():
    """The runner's opt-in helper is a no-op when no RS pid is supplied."""
    with _maybe_sampler(None) as sampler:
        assert sampler is None


def test_maybe_sampler_with_pid_yields_live_sampler():
    """A pid produces a live sampler whose result is populated on exit."""
    with _maybe_sampler(os.getpid()) as sampler:
        assert isinstance(sampler, ResourceSampler)
    assert sampler.result.sampled is True
