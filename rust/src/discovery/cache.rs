//! Bounded TTL cache for discovery documents, keyed by issuer URL.
//!
//! Backed by a [`tokio::sync::RwLock`] so concurrent readers share a fresh
//! entry without contention (DISC-004) while a refresh takes the write lock
//! (DISC-005).
//!
//! The map is keyed by issuer URL; without a bound it grows one entry per
//! distinct issuer forever. A multi-tenant gateway or attacker-supplied issuer
//! header could accumulate entries until the process exhausts memory
//! (unbounded-growth DoS). A max-entries LRU bound caps the map: insertion
//! evicts the least-recently-*used* entry once the cap is exceeded, and read
//! hits refresh recency so a hot entry is not evicted by a flood of cold
//! issuers. Mirrors the Python reference (`py_identity_model.core.jwks_cache`,
//! default 64). A cap of `0` disables the bound (explicit unbounded escape
//! hatch).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::RwLock;

use super::metadata::ProviderMetadata;

/// A cached document paired with the instant it expires. `expires_at` is
/// `None` when the TTL is so large that `Instant::now() + ttl` would overflow
/// (e.g. `Duration::MAX`), in which case the entry never expires.
struct CacheEntry {
    metadata: ProviderMetadata,
    expires_at: Option<Instant>,
    /// Monotonic recency tick; the higher the value, the more recently the entry
    /// was used. Bumped on every read hit and on insert. Interior-mutable
    /// ([`AtomicU64`]) so a read hit can refresh recency while holding only a
    /// shared read lock, preserving the concurrent-reader property (DISC-004).
    last_access: AtomicU64,
}

/// A bounded TTL cache mapping an issuer URL to its parsed [`ProviderMetadata`].
pub(crate) struct Cache {
    entries: RwLock<HashMap<String, CacheEntry>>,
    /// Maximum number of distinct issuer entries retained. `0` means unbounded
    /// (no eviction).
    max_entries: usize,
    /// Source of the monotonic recency ticks stored in each entry.
    access_counter: AtomicU64,
}

impl Cache {
    /// Returns an empty cache bounded to at most `max_entries` distinct issuers.
    /// A `max_entries` of `0` disables the bound (unbounded).
    pub(crate) fn new(max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            max_entries,
            access_counter: AtomicU64::new(0),
        }
    }

    /// Returns the next monotonic recency tick.
    fn next_tick(&self) -> u64 {
        self.access_counter.fetch_add(1, Ordering::Relaxed)
    }

    /// Returns the cached metadata for `key` if present and unexpired
    /// (DISC-004); returns `None` once the TTL has elapsed (DISC-005). A hit
    /// refreshes the entry's LRU recency so it is evicted last.
    pub(crate) async fn get(&self, key: &str) -> Option<ProviderMetadata> {
        let entries = self.entries.read().await;
        let entry = entries.get(key)?;
        // A `None` expiry never elapses; otherwise the entry is fresh until then.
        if entry.expires_at.is_none_or(|at| Instant::now() < at) {
            // Refresh recency under the shared read lock via the atomic tick.
            entry.last_access.store(self.next_tick(), Ordering::Relaxed);
            Some(entry.metadata.clone())
        } else {
            None
        }
    }

    /// Stores `metadata` for `key`, expiring `ttl` from now, then evicts the
    /// least-recently-used entries until the cache is within its bound.
    pub(crate) async fn put(&self, key: String, metadata: ProviderMetadata, ttl: Duration) {
        // `checked_add` guards against an overflow panic for a very large TTL
        // (e.g. `Duration::MAX`); `None` means the entry never expires.
        let expires_at = Instant::now().checked_add(ttl);
        let mut entries = self.entries.write().await;
        // Take the recency tick *after* acquiring the write lock so tick order
        // matches actual insertion order under concurrent puts (ticking before
        // the lock could hand a later insert a smaller tick, skewing the LRU
        // victim). Matches the Go port's `store`.
        let tick = self.next_tick();
        entries.insert(
            key,
            CacheEntry {
                metadata,
                expires_at,
                last_access: AtomicU64::new(tick),
            },
        );
        self.evict_lru(&mut entries);
    }

    /// Evicts least-recently-used entries until `entries` is within
    /// `max_entries`. A `max_entries` of `0` is unbounded and evicts nothing.
    /// Runs under the caller's write lock.
    fn evict_lru(&self, entries: &mut HashMap<String, CacheEntry>) {
        if self.max_entries == 0 {
            return;
        }
        while entries.len() > self.max_entries {
            // The least-recently-used entry has the smallest recency tick. Ties
            // are effectively impossible: every tick is a distinct value handed
            // out by `next_tick`. The scan is O(n) with n <= max_entries.
            let lru_key = entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_access.load(Ordering::Relaxed))
                .map(|(key, _)| key.clone());
            match lru_key {
                Some(key) => {
                    entries.remove(&key);
                }
                None => break,
            }
        }
    }

    /// Test-only: number of cached entries.
    #[cfg(test)]
    pub(crate) async fn entry_count(&self) -> usize {
        self.entries.read().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal metadata value for cache-mechanics tests; contents are
    /// irrelevant here (LRU keys on the issuer, not the payload). Every required
    /// field defaults to empty, so `{}` deserializes.
    fn metadata() -> ProviderMetadata {
        serde_json::from_str("{}").expect("empty metadata deserializes")
    }

    const TTL: Duration = Duration::from_secs(60);

    // The cache never exceeds its configured cap no matter how many distinct
    // issuers are inserted (unbounded-growth DoS bound).
    #[tokio::test]
    async fn size_never_exceeds_cap() {
        let cache = Cache::new(3);
        for i in 0..25 {
            cache
                .put(format!("https://issuer/{i}"), metadata(), TTL)
                .await;
            assert!(
                cache.entry_count().await <= 3,
                "size exceeded cap after inserting entry {i}"
            );
        }
        assert_eq!(cache.entry_count().await, 3);
    }

    // LRU eviction order: the least-recently-*used* entry is evicted first, and a
    // read hit refreshes recency so a hot entry survives a later cold insert.
    #[tokio::test]
    async fn evicts_least_recently_used_and_read_refreshes_recency() {
        let cache = Cache::new(2);
        cache.put("a".to_string(), metadata(), TTL).await;
        cache.put("b".to_string(), metadata(), TTL).await;

        // Read "a" so it becomes more recently used than "b".
        assert!(cache.get("a").await.is_some());

        // Inserting "c" overflows the cap; the LRU entry is now "b".
        cache.put("c".to_string(), metadata(), TTL).await;

        assert!(cache.get("a").await.is_some(), "recently-read a survives");
        assert!(cache.get("c").await.is_some(), "newest c present");
        assert!(
            cache.get("b").await.is_none(),
            "least-recently-used b evicted"
        );
        assert_eq!(cache.entry_count().await, 2);
    }

    // A cap of 0 disables the bound entirely (backward-compat unbounded mode).
    #[tokio::test]
    async fn zero_cap_is_unbounded() {
        let cache = Cache::new(0);
        for i in 0..100 {
            cache.put(format!("issuer-{i}"), metadata(), TTL).await;
        }
        assert_eq!(cache.entry_count().await, 100, "cap 0 evicts nothing");
    }

    // TTL expiry is unchanged by the LRU layer: an expired entry is not served.
    #[tokio::test]
    async fn expired_entry_is_not_served() {
        let cache = Cache::new(8);
        cache
            .put("a".to_string(), metadata(), Duration::from_millis(10))
            .await;
        assert!(cache.get("a").await.is_some(), "fresh before TTL");
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(cache.get("a").await.is_none(), "expired after TTL");
    }
}
