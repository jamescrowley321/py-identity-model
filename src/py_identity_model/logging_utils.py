"""
Logging utilities for py-identity-model.

This module provides utilities for safely logging sensitive information,
ensuring that tokens, secrets, and other sensitive data are properly redacted.
"""

from __future__ import annotations

from typing import Any


def redact_sensitive(data: dict[str, Any]) -> dict[str, Any]:
    """
    Redact sensitive information from a dictionary for safe logging.

    Args:
        data: Dictionary that may contain sensitive information.

    Returns:
        A new dictionary with sensitive values redacted.

    Example:
        >>> data = {"client_id": "my-client", "client_secret": "secret123"}
        >>> redact_sensitive(data)
        {'client_id': 'my-client', 'client_secret': '***REDACTED***'}
    """
    sensitive_keys = {
        "client_secret",
        "password",
        "access_token",
        "refresh_token",
        "id_token",
        "token",
        "authorization",
        "secret",
        "api_key",
        "apikey",
    }

    redacted = data.copy()
    for key in redacted:
        key_lower = key.lower().replace("-", "_")
        if key_lower in sensitive_keys:
            redacted[key] = "***REDACTED***"
        elif isinstance(redacted[key], str) and len(redacted[key]) > 100:
            # Likely a token or long sensitive string - truncate and redact
            redacted[key] = redacted[key][:20] + "...***REDACTED***"

    return redacted


def redact_token(token: str) -> str:
    """
    Redact a token for safe logging (shows first and last 4 characters).

    Args:
        token: The token string to redact.

    Returns:
        Redacted token showing only first and last 4 characters.

    Example:
        >>> redact_token("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...")
        'eyJh...VCJ9'
    """
    if len(token) < 20:
        return "***REDACTED***"
    return f"{token[:4]}...{token[-4:]}"


def redact_url(url: str) -> str:
    """
    Redact sensitive information from URLs (e.g., query parameters).

    Currently returns the URL as-is, but could be extended to redact
    query parameters like access_token, client_secret, etc.

    Args:
        url: The URL to redact.

    Returns:
        The URL with sensitive parts redacted.
    """
    # For now, return as-is. Could be extended to parse and redact query params
    return url


__all__ = ["redact_sensitive", "redact_token", "redact_url"]
