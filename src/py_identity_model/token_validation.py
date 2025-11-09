"""Token validation module - re-exports from sync for backward compatibility."""

from .sync.token_validation import TokenValidationConfig, validate_token


__all__ = ["TokenValidationConfig", "validate_token"]
