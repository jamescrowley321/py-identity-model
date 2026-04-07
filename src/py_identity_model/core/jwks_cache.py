"""
JWKS cache TTL configuration and cache entry logic.

This module provides TTL-based caching for JWKS responses, supporting
automatic cache expiry and forced refresh on key rotation (RFC 7517 §5).

Environment Variables:
    JWKS_CACHE_TTL: Cache TTL in seconds (default: 86400 / 24 hours)
"""

from __future__ import annotations

from dataclasses import dataclass
import os
import time
from typing import TYPE_CHECKING

from ..logging_config import logger


if TYPE_CHECKING:
    from ..core.models import JwksResponse


DEFAULT_JWKS_CACHE_TTL_SECONDS: float = 86400.0  # 24 hours


def get_jwks_cache_ttl() -> float:
    """Get JWKS cache TTL from environment variable or default.

    Returns:
        Cache TTL in seconds.
    """
    return float(os.getenv("JWKS_CACHE_TTL", str(DEFAULT_JWKS_CACHE_TTL_SECONDS)))


@dataclass
class JwksCacheEntry:
    """A cached JWKS response with timestamp."""

    response: JwksResponse
    cached_at: float


def is_cache_expired(entry: JwksCacheEntry, ttl: float) -> bool:
    """Check if a cache entry has expired.

    Args:
        entry: The cache entry to check.
        ttl: TTL in seconds.

    Returns:
        True if the entry is expired.
    """
    expired = (time.time() - entry.cached_at) >= ttl
    if expired:
        logger.debug(
            "JWKS cache entry expired (age=%.1fs, ttl=%.1fs)",
            time.time() - entry.cached_at,
            ttl,
        )
    return expired


__all__ = [
    "DEFAULT_JWKS_CACHE_TTL_SECONDS",
    "JwksCacheEntry",
    "get_jwks_cache_ttl",
    "is_cache_expired",
]
