"""
JWKS cache TTL configuration and cache entry logic.

This module provides TTL-based caching for JWKS responses, supporting
automatic cache expiry and forced refresh on key rotation (RFC 7517 §5).

TTL resolution order:
1. ``Cache-Control: max-age=N`` from the provider's JWKS HTTP response
2. ``JWKS_CACHE_TTL`` environment variable (seconds)
3. Default: 86400 (24 hours)

The provider's cache header is preferred because providers set ``max-age``
based on their key rotation schedule (e.g., Google uses ``max-age=19800``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
import os
import re
import time
from typing import TYPE_CHECKING

from ..logging_config import logger


if TYPE_CHECKING:
    from ..core.models import JwksResponse

DEFAULT_JWKS_CACHE_TTL_SECONDS: float = 86400.0  # 24 hours
MIN_CACHE_TTL_SECONDS: float = 60.0
MAX_CACHE_TTL_SECONDS: float = 86400.0

_env_ttl: float | None = None
_MAX_AGE_RE = re.compile(r"max-age=(\d+)", re.IGNORECASE)


def _get_env_ttl() -> float:
    """Read JWKS_CACHE_TTL from env once, cache the result."""
    global _env_ttl  # noqa: PLW0603
    if _env_ttl is None:
        _env_ttl = float(
            os.getenv("JWKS_CACHE_TTL", str(DEFAULT_JWKS_CACHE_TTL_SECONDS))
        )
    return _env_ttl


def parse_max_age(cache_control: str | None) -> float | None:
    """Extract max-age from a Cache-Control header value.

    Returns:
        The max-age in seconds, or None if not present/parseable.
    """
    if not cache_control:
        return None
    match = _MAX_AGE_RE.search(cache_control)
    if match:
        return float(match.group(1))
    return None


def resolve_ttl(cache_control: str | None) -> float:
    """Determine the cache TTL from HTTP headers or config.

    Priority: Cache-Control max-age > JWKS_CACHE_TTL env var > default.
    Result is clamped to [60s, 86400s].
    """
    max_age = parse_max_age(cache_control)
    if max_age is not None:
        ttl = max(MIN_CACHE_TTL_SECONDS, min(max_age, MAX_CACHE_TTL_SECONDS))
        logger.debug(
            "Using provider Cache-Control max-age=%s (clamped to %.0fs)", max_age, ttl
        )
        return ttl
    return _get_env_ttl()


@dataclass
class JwksCacheEntry:
    """A cached JWKS response with timestamp and TTL."""

    response: JwksResponse
    cached_at: float
    ttl: float = field(default_factory=_get_env_ttl)


def is_cache_expired(entry: JwksCacheEntry) -> bool:
    """Check if a cache entry has expired using its own TTL.

    Args:
        entry: The cache entry to check.

    Returns:
        True if the entry is expired.
    """
    age = time.time() - entry.cached_at
    expired = age >= entry.ttl
    if expired:
        logger.debug("JWKS cache entry expired (age=%.1fs, ttl=%.1fs)", age, entry.ttl)
    return expired


__all__ = [
    "DEFAULT_JWKS_CACHE_TTL_SECONDS",
    "JwksCacheEntry",
    "is_cache_expired",
    "parse_max_age",
    "resolve_ttl",
]
