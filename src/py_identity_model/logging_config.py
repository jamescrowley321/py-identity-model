"""
Logging configuration for py-identity-model.

This module provides utilities to configure logging for the library,
allowing users to enable debug logging and customize the log output.
"""

from __future__ import annotations

import logging
from typing import Optional

# Library logger - uses NullHandler by default (no output)
logger = logging.getLogger("py_identity_model")
logger.addHandler(logging.NullHandler())


def configure_logging(
    level: int = logging.WARNING,
    format: Optional[str] = None,
    handler: Optional[logging.Handler] = None,
) -> None:
    """
    Configure logging for py-identity-model.

    By default, py-identity-model uses a NullHandler which produces no output.
    Call this function to enable logging output.

    Args:
        level: Logging level (e.g., logging.DEBUG, logging.INFO).
               Defaults to logging.WARNING.
        format: Log format string. Defaults to a standard format with timestamp.
        handler: Custom handler (defaults to StreamHandler if not provided).

    Example:
        >>> import logging
        >>> from py_identity_model.logging_config import configure_logging
        >>> # Enable debug logging
        >>> configure_logging(level=logging.DEBUG)
        >>> # Or use standard Python logging
        >>> logging.basicConfig(level=logging.DEBUG)
    """
    if format is None:
        format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    if handler is None:
        handler = logging.StreamHandler()

    handler.setFormatter(logging.Formatter(format))

    # Remove any existing handlers to avoid duplicates
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.setLevel(level)


__all__ = ["logger", "configure_logging"]
