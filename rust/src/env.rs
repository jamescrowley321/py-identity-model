//! Internal helpers for reading numeric configuration from the environment.
//!
//! Kept deliberately small and pure so the parsing rules can be unit-tested
//! without mutating the process environment: `std::env::set_var` is `unsafe` in
//! edition 2024 and races the other tests that run concurrently in the same
//! process. The public wrapper reads the variable; the pure parser does the
//! validation.

/// Parses a max-cache-entries value from an already-read env string.
///
/// Resolution rules (kept lenient so a misconfigured deployment degrades to the
/// safe default rather than panicking at first cache access):
///
/// - absent / empty / whitespace / unparseable / negative → `default`
/// - `"0"` → `0`, the explicit **unbounded** escape hatch (no size cap)
/// - any positive integer → that value, used as the LRU cap
pub(crate) fn parse_max_cache_entries(raw: Option<&str>, default: usize) -> usize {
    match raw {
        Some(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                default
            } else {
                // A leading '-' or non-digit fails `usize::parse`, falling back
                // to the default; `"0"` parses to 0 (unbounded).
                trimmed.parse::<usize>().unwrap_or(default)
            }
        }
        None => default,
    }
}

/// Reads `var` from the environment and parses it as a max-cache-entries value,
/// falling back to `default` when unset or invalid. See
/// [`parse_max_cache_entries`] for the resolution rules.
pub(crate) fn max_cache_entries_from_env(var: &str, default: usize) -> usize {
    parse_max_cache_entries(std::env::var(var).ok().as_deref(), default)
}

#[cfg(test)]
mod tests {
    use super::parse_max_cache_entries;

    // Absent, empty, whitespace, and unparseable values fall back to the default
    // so a misconfigured env cannot silently disable or corrupt the cache bound.
    #[test]
    fn falls_back_to_default_on_absent_or_garbage() {
        assert_eq!(parse_max_cache_entries(None, 64), 64);
        assert_eq!(parse_max_cache_entries(Some(""), 64), 64);
        assert_eq!(parse_max_cache_entries(Some("   "), 64), 64);
        assert_eq!(parse_max_cache_entries(Some("abc"), 64), 64);
        assert_eq!(parse_max_cache_entries(Some("12x"), 64), 64);
        assert_eq!(parse_max_cache_entries(Some("-5"), 64), 64);
        assert_eq!(parse_max_cache_entries(Some("1.5"), 64), 64);
    }

    // `0` is honored as the explicit unbounded escape hatch; positive integers
    // (with surrounding whitespace tolerated) are used verbatim.
    #[test]
    fn honors_zero_and_positive_values() {
        assert_eq!(parse_max_cache_entries(Some("0"), 64), 0);
        assert_eq!(parse_max_cache_entries(Some("1"), 64), 1);
        assert_eq!(parse_max_cache_entries(Some("128"), 64), 128);
        assert_eq!(parse_max_cache_entries(Some(" 32 "), 64), 32);
    }
}
