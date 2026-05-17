"""
Proves the JWKS/discovery cache rejects unsafe env config and bounds memory.

Two pre-existing structural bugs the cache primitive shipped with:

1. **Env-provided TTL was not clamped.** ``JWKS_CACHE_TTL=0`` silently
   disabled the cache (every entry instantly expired → refetch on every
   validation → DoS amplifier). ``JWKS_CACHE_TTL=2592000`` silently
   disabled the documented 24h ceiling on key-rotation latency. Garbage
   values raised ``ValueError`` at first cache access — process crash on
   bad config rather than fail-fast at import.

2. **Cache dicts grew without bound.** Any deployment with caller-influenced
   ``disco_doc_address`` (multi-tenant gateways, attacker-supplied issuer
   headers) could grow the dict forever. At ~5KB per entry, a few thousand
   unique addresses leaked tens of MB.

These tests pin the fixes:
- TTL env values clamped to [MIN, MAX]; garbage falls back to default.
- Cache size capped at ``JWKS_CACHE_MAX_ENTRIES`` (default 64).
- FIFO eviction targets the oldest entry, not the newest or a random one.
- Re-storing a URI (refresh) moves it to "newest" so subsequent eviction
  doesn't target a just-refreshed entry.
"""

import time

import httpx
import pytest
import respx

from py_identity_model.core.jwks_cache import (
    DEFAULT_DISCO_CACHE_TTL_SECONDS,
    DEFAULT_JWKS_CACHE_TTL_SECONDS,
    DEFAULT_KID_MISS_REFRESH_COOLDOWN_SECONDS,
    DEFAULT_MAX_CACHE_ENTRIES,
    MAX_CACHE_TTL_SECONDS,
    MAX_KID_MISS_COOLDOWN_SECONDS,
    MIN_CACHE_TTL_SECONDS,
    MIN_KID_MISS_COOLDOWN_SECONDS,
    JwksCacheEntry,
    _reset_env_for_testing,
    apply_jwks_cache_outcome,
    get_kid_miss_cooldown,
    get_max_cache_entries,
    resolve_disco_ttl,
    resolve_ttl,
)
from py_identity_model.core.models import JsonWebKey, JwksResponse
from py_identity_model.sync import token_validation as sync_tv
from py_identity_model.sync.token_validation import (
    _get_cached_jwks,
    clear_discovery_cache,
    clear_jwks_cache,
)

from .token_validation_helpers import generate_rsa_keypair


@pytest.fixture(autouse=True)
def _reset_state():
    clear_discovery_cache()
    clear_jwks_cache()
    _reset_env_for_testing()
    yield
    clear_discovery_cache()
    clear_jwks_cache()
    _reset_env_for_testing()


# ============================================================================
# TTL env clamping: zero, negative, overflow, and garbage must not break
# the documented invariants.
# ============================================================================

JWKS_TTL_CLAMP_CASES = [
    pytest.param("0", MIN_CACHE_TTL_SECONDS, id="zero-clamped-to-min"),
    pytest.param("-5", MIN_CACHE_TTL_SECONDS, id="negative-clamped-to-min"),
    pytest.param("30", MIN_CACHE_TTL_SECONDS, id="below-min-clamped-up"),
    pytest.param("60", MIN_CACHE_TTL_SECONDS, id="at-min-preserved"),
    pytest.param("3600", 3600.0, id="middle-passthrough"),
    pytest.param("86400", MAX_CACHE_TTL_SECONDS, id="at-max-preserved"),
    pytest.param("999999", MAX_CACHE_TTL_SECONDS, id="above-max-clamped-down"),
    pytest.param("2592000", MAX_CACHE_TTL_SECONDS, id="month-clamped-down"),
]


class TestEnvTtlClamping:
    @pytest.mark.parametrize(("env_value", "expected"), JWKS_TTL_CLAMP_CASES)
    def test_jwks_ttl_env_clamped(self, env_value, expected, monkeypatch):
        """resolve_ttl(None) reads the env path; values outside [MIN, MAX]
        must be clamped to the documented bounds, not honored raw."""
        monkeypatch.setenv("JWKS_CACHE_TTL", env_value)
        _reset_env_for_testing()
        assert resolve_ttl(None) == expected

    @pytest.mark.parametrize(("env_value", "expected"), JWKS_TTL_CLAMP_CASES)
    def test_disco_ttl_env_clamped(self, env_value, expected, monkeypatch):
        monkeypatch.setenv("DISCO_CACHE_TTL", env_value)
        _reset_env_for_testing()
        assert resolve_disco_ttl(None) == expected

    def test_garbage_jwks_ttl_falls_back_to_default(self, monkeypatch):
        """Malformed env must not crash the process; a warning + default is
        the correct fail-safe."""
        monkeypatch.setenv("JWKS_CACHE_TTL", "60s")
        _reset_env_for_testing()
        assert resolve_ttl(None) == DEFAULT_JWKS_CACHE_TTL_SECONDS

    def test_empty_jwks_ttl_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("JWKS_CACHE_TTL", "")
        _reset_env_for_testing()
        assert resolve_ttl(None) == DEFAULT_JWKS_CACHE_TTL_SECONDS

    def test_garbage_disco_ttl_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("DISCO_CACHE_TTL", "not-a-number")
        _reset_env_for_testing()
        assert resolve_disco_ttl(None) == DEFAULT_DISCO_CACHE_TTL_SECONDS

    def test_unset_jwks_ttl_uses_default(self, monkeypatch):
        monkeypatch.delenv("JWKS_CACHE_TTL", raising=False)
        _reset_env_for_testing()
        assert resolve_ttl(None) == DEFAULT_JWKS_CACHE_TTL_SECONDS


# ============================================================================
# KID_MISS_REFRESH_COOLDOWN env parsing must apply the same fail-safe pattern
# as JWKS_CACHE_TTL — without it, ``=abc`` crashes every kid-miss caller,
# ``=nan`` makes the cooldown permanent (``now-last >= nan`` is False forever),
# and ``=999999`` silently sets a multi-day cooldown that exceeds the
# documented rotation-latency expectation.
# ============================================================================


COOLDOWN_CLAMP_CASES = [
    pytest.param(
        "0", MIN_KID_MISS_COOLDOWN_SECONDS, id="zero-explicit-opt-out-honored"
    ),
    pytest.param("-5", MIN_KID_MISS_COOLDOWN_SECONDS, id="negative-clamped-to-min"),
    pytest.param("1", 1.0, id="middle-passthrough"),
    pytest.param("3600", MAX_KID_MISS_COOLDOWN_SECONDS, id="at-max-preserved"),
    pytest.param("999999", MAX_KID_MISS_COOLDOWN_SECONDS, id="above-max-clamped-down"),
]


class TestKidMissCooldownEnvParsing:
    @pytest.mark.parametrize(("env_value", "expected"), COOLDOWN_CLAMP_CASES)
    def test_cooldown_env_clamped(self, env_value, expected, monkeypatch):
        monkeypatch.setenv("KID_MISS_REFRESH_COOLDOWN", env_value)
        _reset_env_for_testing()
        assert get_kid_miss_cooldown() == expected

    def test_garbage_falls_back_to_default(self, monkeypatch):
        """``=abc`` must not crash with ValueError at first kid-miss caller."""
        monkeypatch.setenv("KID_MISS_REFRESH_COOLDOWN", "abc")
        _reset_env_for_testing()
        assert get_kid_miss_cooldown() == DEFAULT_KID_MISS_REFRESH_COOLDOWN_SECONDS

    def test_units_suffix_falls_back_to_default(self, monkeypatch):
        """``=5s`` is plausible operator config and must fail safe."""
        monkeypatch.setenv("KID_MISS_REFRESH_COOLDOWN", "5s")
        _reset_env_for_testing()
        assert get_kid_miss_cooldown() == DEFAULT_KID_MISS_REFRESH_COOLDOWN_SECONDS

    def test_nan_falls_back_to_default(self, monkeypatch):
        """``=nan`` must not produce a permanent cooldown — the comparison
        ``now - last >= nan`` is False forever, silently disabling refresh."""
        monkeypatch.setenv("KID_MISS_REFRESH_COOLDOWN", "nan")
        _reset_env_for_testing()
        assert get_kid_miss_cooldown() == DEFAULT_KID_MISS_REFRESH_COOLDOWN_SECONDS

    def test_infinity_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("KID_MISS_REFRESH_COOLDOWN", "inf")
        _reset_env_for_testing()
        assert get_kid_miss_cooldown() == DEFAULT_KID_MISS_REFRESH_COOLDOWN_SECONDS

    def test_empty_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("KID_MISS_REFRESH_COOLDOWN", "")
        _reset_env_for_testing()
        assert get_kid_miss_cooldown() == DEFAULT_KID_MISS_REFRESH_COOLDOWN_SECONDS

    def test_unset_uses_default(self, monkeypatch):
        monkeypatch.delenv("KID_MISS_REFRESH_COOLDOWN", raising=False)
        _reset_env_for_testing()
        assert get_kid_miss_cooldown() == DEFAULT_KID_MISS_REFRESH_COOLDOWN_SECONDS


# ============================================================================
# Bounded cache: size capped, FIFO eviction targets oldest entry.
# ============================================================================


def _make_jwks_response(kid: str) -> JwksResponse:
    """Build a successful, cacheable JWKS response carrying a single key."""
    key_dict, _ = generate_rsa_keypair()
    key_dict["kid"] = kid
    jwk = JsonWebKey(
        kty=key_dict["kty"],
        kid=key_dict["kid"],
        alg=key_dict["alg"],
        use=key_dict["use"],
        n=key_dict["n"],
        e=key_dict["e"],
    )
    return JwksResponse(
        is_successful=True,
        keys=[jwk],
        cache_control="max-age=3600",
    )


class TestBoundedCacheSize:
    def test_max_entries_env_override(self, monkeypatch):
        monkeypatch.setenv("JWKS_CACHE_MAX_ENTRIES", "8")
        _reset_env_for_testing()
        assert get_max_cache_entries() == 8  # noqa: PLR2004

    def test_max_entries_default_when_unset(self, monkeypatch):
        monkeypatch.delenv("JWKS_CACHE_MAX_ENTRIES", raising=False)
        _reset_env_for_testing()
        assert get_max_cache_entries() == DEFAULT_MAX_CACHE_ENTRIES

    def test_max_entries_falls_back_on_garbage(self, monkeypatch):
        monkeypatch.setenv("JWKS_CACHE_MAX_ENTRIES", "abc")
        _reset_env_for_testing()
        assert get_max_cache_entries() == DEFAULT_MAX_CACHE_ENTRIES

    def test_max_entries_falls_back_on_non_positive(self, monkeypatch):
        monkeypatch.setenv("JWKS_CACHE_MAX_ENTRIES", "0")
        _reset_env_for_testing()
        assert get_max_cache_entries() == DEFAULT_MAX_CACHE_ENTRIES

    def test_jwks_cache_size_capped_under_overflow(self, monkeypatch):
        """Insert max+5 distinct URIs into the cache via the apply helper —
        post-insert the cache holds exactly ``max`` entries."""
        monkeypatch.setenv("JWKS_CACHE_MAX_ENTRIES", "5")
        _reset_env_for_testing()
        cache: dict[str, JwksCacheEntry] = {}

        for i in range(10):
            apply_jwks_cache_outcome(
                cache,
                jwks_uri=f"https://op-{i}.example/jwks",
                response=_make_jwks_response(f"kid-{i}"),
                now=time.time(),
            )

        assert len(cache) == 5  # noqa: PLR2004
        # FIFO eviction: the *oldest* 5 inserts are gone, *newest* 5 remain.
        remaining_uris = set(cache.keys())
        expected_uris = {f"https://op-{i}.example/jwks" for i in range(5, 10)}
        assert remaining_uris == expected_uris

    def test_refresh_of_existing_uri_does_not_count_as_new_entry(self, monkeypatch):
        """Re-storing a URI must move it to the end of insertion order so
        a subsequent overflow doesn't immediately evict a just-refreshed
        entry. This is the difference between OK-FIFO and broken-FIFO."""
        monkeypatch.setenv("JWKS_CACHE_MAX_ENTRIES", "3")
        _reset_env_for_testing()
        cache: dict[str, JwksCacheEntry] = {}

        # Fill to capacity in known order.
        for i in range(3):
            apply_jwks_cache_outcome(
                cache,
                jwks_uri=f"https://op-{i}.example/jwks",
                response=_make_jwks_response(f"kid-{i}"),
                now=time.time(),
            )
        assert list(cache.keys()) == [
            "https://op-0.example/jwks",
            "https://op-1.example/jwks",
            "https://op-2.example/jwks",
        ]

        # Refresh op-0 (the oldest). It should move to the newest position.
        apply_jwks_cache_outcome(
            cache,
            jwks_uri="https://op-0.example/jwks",
            response=_make_jwks_response("kid-0-rotated"),
            now=time.time(),
        )
        assert list(cache.keys()) == [
            "https://op-1.example/jwks",
            "https://op-2.example/jwks",
            "https://op-0.example/jwks",
        ]

        # Add a fourth distinct URI. Eviction should now target op-1 (the
        # oldest non-refreshed), not the just-refreshed op-0.
        apply_jwks_cache_outcome(
            cache,
            jwks_uri="https://op-3.example/jwks",
            response=_make_jwks_response("kid-3"),
            now=time.time(),
        )
        assert set(cache.keys()) == {
            "https://op-2.example/jwks",
            "https://op-0.example/jwks",
            "https://op-3.example/jwks",
        }

    @respx.mock
    def test_end_to_end_jwks_cache_capped(self, monkeypatch):
        """End-to-end via _get_cached_jwks: hammering N+5 unique URIs from
        the real call site enforces the same bound as the apply helper
        directly. Catches any path that bypasses _enforce_size_limit."""
        monkeypatch.setenv("JWKS_CACHE_MAX_ENTRIES", "4")
        _reset_env_for_testing()

        urls_to_visit = [f"https://op-{i}.example/jwks" for i in range(9)]
        key_dict, _ = generate_rsa_keypair()
        for url in urls_to_visit:
            respx.get(url).mock(
                return_value=httpx.Response(
                    200,
                    json={"keys": [key_dict]},
                    headers={"Cache-Control": "max-age=3600"},
                )
            )

        for url in urls_to_visit:
            response = _get_cached_jwks(url)
            assert response.is_successful is True

        assert len(sync_tv._jwks_cache) == 4  # noqa: PLR2004
        # Newest four URIs are the survivors.
        assert set(sync_tv._jwks_cache.keys()) == set(urls_to_visit[-4:])
