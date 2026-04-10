"""Unit tests for JWKS cache TTL logic — parsing, resolution, expiry, and concurrency."""
# ruff: noqa: PLR2004

import time
from unittest.mock import MagicMock

from py_identity_model.core.jwks_cache import (
    DEFAULT_JWKS_CACHE_TTL_SECONDS,
    MAX_CACHE_TTL_SECONDS,
    MIN_CACHE_TTL_SECONDS,
    JwksCacheEntry,
    is_cache_expired,
    parse_max_age,
    resolve_ttl,
)


class TestParseMaxAge:
    def test_standard_header(self):
        assert parse_max_age("max-age=3600") == 3600.0

    def test_with_other_directives(self):
        assert parse_max_age("public, max-age=19800, must-revalidate") == 19800.0

    def test_case_insensitive(self):
        assert parse_max_age("Max-Age=300") == 300.0

    def test_no_max_age(self):
        assert parse_max_age("no-cache, no-store") is None

    def test_none_header(self):
        assert parse_max_age(None) is None

    def test_empty_string(self):
        assert parse_max_age("") is None

    def test_zero(self):
        assert parse_max_age("max-age=0") == 0.0


class TestResolveTtl:
    def test_uses_cache_control_when_present(self):
        ttl = resolve_ttl("max-age=3600")
        assert ttl == 3600.0

    def test_clamps_to_minimum(self):
        ttl = resolve_ttl("max-age=5")
        assert ttl == MIN_CACHE_TTL_SECONDS

    def test_clamps_to_maximum(self):
        ttl = resolve_ttl("max-age=999999")
        assert ttl == MAX_CACHE_TTL_SECONDS

    def test_falls_back_to_env_default(self):
        ttl = resolve_ttl(None)
        assert ttl == DEFAULT_JWKS_CACHE_TTL_SECONDS

    def test_google_typical_value(self):
        """Google JWKS uses max-age=19800 (5.5 hours)."""
        ttl = resolve_ttl("public, max-age=19800")
        assert ttl == 19800.0

    def test_zero_max_age_clamps_to_minimum(self):
        ttl = resolve_ttl("max-age=0")
        assert ttl == MIN_CACHE_TTL_SECONDS


class TestCacheEntry:
    def _make_entry(self, age_seconds: float = 0, ttl: float = 300) -> JwksCacheEntry:
        mock_response = MagicMock()
        return JwksCacheEntry(
            response=mock_response,
            cached_at=time.time() - age_seconds,
            ttl=ttl,
        )

    def test_fresh_entry_not_expired(self):
        entry = self._make_entry(age_seconds=0, ttl=300)
        assert not is_cache_expired(entry)

    def test_expired_entry(self):
        entry = self._make_entry(age_seconds=301, ttl=300)
        assert is_cache_expired(entry)

    def test_exactly_at_ttl_is_expired(self):
        entry = self._make_entry(age_seconds=300, ttl=300)
        assert is_cache_expired(entry)

    def test_entry_stores_custom_ttl(self):
        entry = self._make_entry(ttl=7200)
        assert entry.ttl == 7200


class TestMultiProviderCacheIsolation:
    """Verify that cache entries for different providers don't interfere."""

    def test_different_ttls_per_provider(self):
        """Two providers with different Cache-Control values get separate TTLs."""
        google_ttl = resolve_ttl("max-age=19800")
        auth0_ttl = resolve_ttl("max-age=3600")

        google_entry = JwksCacheEntry(
            response=MagicMock(), cached_at=time.time(), ttl=google_ttl
        )
        auth0_entry = JwksCacheEntry(
            response=MagicMock(), cached_at=time.time(), ttl=auth0_ttl
        )

        assert google_entry.ttl == 19800.0
        assert auth0_entry.ttl == 3600.0
        assert not is_cache_expired(google_entry)
        assert not is_cache_expired(auth0_entry)

    def test_one_provider_expired_other_not(self):
        """Provider with short TTL expires while long-TTL provider stays cached."""
        now = time.time()
        short_entry = JwksCacheEntry(response=MagicMock(), cached_at=now - 120, ttl=60)
        long_entry = JwksCacheEntry(response=MagicMock(), cached_at=now - 120, ttl=3600)

        assert is_cache_expired(short_entry)
        assert not is_cache_expired(long_entry)
