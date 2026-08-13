"""Unit tests for the load-runner result model — TH-1.5 (#474, epic #462).

These cover the pure-logic properties of :class:`LoadResult` without needing the
``load`` dependency group: the module imports cleanly in the plain unit env
because :mod:`runner` spawns Locust in a subprocess and never imports it at
top level. The end-to-end Locust proof lives in ``src/tests/load``.
"""

from __future__ import annotations

import pytest

from ..load.runner import LoadResult


pytestmark = pytest.mark.unit


def _result(**overrides) -> LoadResult:
    base = {
        "scenario_id": "S0",
        "title": "unit",
        "num_requests": 0,
        "num_failures": 0,
        "rps": 0.0,
        "p50_ms": 0.0,
        "p95_ms": 0.0,
        "p99_ms": 0.0,
        "p999_ms": 0.0,
        "server_errors": 0,
        "steady_state": True,
    }
    base.update(overrides)
    return LoadResult(**base)


class TestCacheHitRate:
    def test_empty_window_reports_zero_not_one(self):
        """An empty/failed-scrape window must NOT read as a perfect 100%.

        Reporting 1.0 for ``total == 0`` would let a broken ``/metrics`` scrape
        masquerade as a warm cache under a ``min_cache_hit_rate`` gate.
        """
        assert _result(cache_metrics={}).cache_hit_rate == 0.0

    def test_all_hits_is_one(self):
        r = _result(cache_metrics={"disco_hits": 3, "jwks_hits": 7})
        assert r.cache_hit_rate == 1.0

    def test_mixed_hits_and_misses(self):
        r = _result(
            cache_metrics={
                "disco_hits": 1,
                "disco_misses": 1,
                "jwks_hits": 1,
                "jwks_misses": 1,
            }
        )
        two_hits_two_misses = 2 / 4
        assert r.cache_hit_rate == two_hits_two_misses

    def test_all_misses_is_zero(self):
        # After the counter fix an all-error window records its failed fetches as
        # misses, so this is the storm case — it must read 0.0, not 1.0.
        r = _result(cache_metrics={"disco_misses": 4, "jwks_misses": 6})
        assert r.cache_hit_rate == 0.0


class TestAlgCostRatio:
    def test_ratio_of_two_classes(self):
        rs256_p95, es256_p95 = 5.0, 15.0
        r = _result(
            latency_by_class={
                "valid": {"p95": rs256_p95},
                "valid_es256": {"p95": es256_p95},
            }
        )
        assert r.alg_cost_ratio("valid_es256", "valid") == es256_p95 / rs256_p95

    def test_missing_class_returns_none(self):
        r = _result(latency_by_class={"valid": {"p95": 5.0}})
        assert r.alg_cost_ratio("valid_es256", "valid") is None

    def test_zero_denominator_returns_none(self):
        r = _result(
            latency_by_class={
                "valid": {"p95": 0.0},
                "valid_es256": {"p95": 5.0},
            }
        )
        assert r.alg_cost_ratio("valid_es256", "valid") is None


def test_p999_is_a_reported_field():
    """p999 (design §5 metric) is carried on the result, not silently dropped."""
    p99, p999 = 10.0, 25.0
    r = _result(p99_ms=p99, p999_ms=p999)
    assert r.p999_ms == p999
    assert r.p999_ms >= r.p99_ms
