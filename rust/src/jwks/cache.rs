//! Bounded TTL cache for JWK Sets, keyed by `jwks_uri`.
//!
//! Backed by a [`tokio::sync::RwLock`] so concurrent readers share a fresh entry
//! without contention (JWKS-005) while a refresh takes the write lock. A
//! [`Cache::invalidate`] drops an entry so the next fetch re-fetches from the
//! provider (JWKS-006).
//!
//! Two hardening properties layered on top of the plain TTL map:
//!
//! - **Max-entries LRU bound.** The map is keyed by `jwks_uri`; without a cap it
//!   grows one entry per distinct URI forever. A multi-tenant gateway or an
//!   attacker able to steer resolution at attacker-chosen URIs could accumulate
//!   entries until the process exhausts memory (unbounded-growth DoS). Insertion
//!   evicts the least-recently-*used* entry once the cap is exceeded; read hits
//!   refresh recency so a hot entry is not evicted merely because a flood of
//!   distinct cold URIs was read after it. Mirrors the Python reference
//!   (`py_identity_model.core.jwks_cache`, default 64). A cap of `0` disables the
//!   bound (explicit unbounded escape hatch).
//! - **Single-flight.** Concurrent cache-misses for the *same* `jwks_uri`
//!   collapse to a single outbound fetch instead of each firing its own,
//!   mirroring the Go reference's `singleflight` (`go/pkg/jwks`).
//!
//! Both sidecars are bounded too, so neither reintroduces the unbounded growth
//! the entry bound closes: the refresh-cooldown map (`last_refresh`) is pruned
//! when its entry is evicted *and* independently capped at `max_entries` in
//! [`Cache::mark_refresh`] (a failed `force_refresh` can otherwise strand a
//! record with no backing entry that entry-eviction never reclaims), and the
//! single-flight gate map (`in_flight`) is released through an RAII
//! [`FlightGuard`] so a fetch cancelled at an `await` cannot strand its gate.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, RwLock};

use super::key::JsonWebKeySet;

/// A cached key set paired with the instant it expires. `expires_at` is `None`
/// when the TTL is so large that `Instant::now() + ttl` would overflow (e.g.
/// `Duration::MAX`), in which case the entry never expires.
struct CacheEntry {
    key_set: JsonWebKeySet,
    expires_at: Option<Instant>,
    /// Monotonic recency tick; the higher the value, the more recently the entry
    /// was used. Bumped on every read hit and on insert. Interior-mutable
    /// ([`AtomicU64`]) so a read hit can refresh recency while holding only a
    /// shared read lock, preserving the concurrent-reader property (JWKS-005)
    /// rather than upgrading every cache hit to a write lock.
    last_access: AtomicU64,
}

/// A bounded TTL cache mapping a `jwks_uri` to its parsed [`JsonWebKeySet`].
pub(crate) struct Cache {
    entries: RwLock<HashMap<String, CacheEntry>>,
    /// Records when each `jwks_uri` was last refreshed, throttling automatic
    /// refreshes so an unknown `kid` cannot drive unbounded re-fetches (see
    /// [`Cache::refresh_throttled`]). Pruned when the corresponding entry is
    /// evicted and independently capped at `max_entries` in
    /// [`Cache::mark_refresh`], so a failed `force_refresh` — which leaves a
    /// record with no backing entry — cannot strand records without bound.
    last_refresh: RwLock<HashMap<String, Instant>>,
    /// Maximum number of distinct `jwks_uri` entries retained. `0` means
    /// unbounded (no eviction).
    max_entries: usize,
    /// Source of the monotonic recency ticks stored in each entry.
    access_counter: AtomicU64,
    /// Per-URI single-flight gates. A cache-miss acquires the gate for its URI
    /// so concurrent misses for the same URI serialize behind one fetch; the
    /// waiters then observe the populated cache instead of fetching again. The
    /// map holds only URIs with a fetch in flight and is released via the RAII
    /// [`FlightGuard`] returned by [`Cache::flight_gate`] — so even a fetch
    /// cancelled at an `await` cannot strand its gate. Its size at any instant is
    /// therefore the number of *concurrently in-flight* distinct-URI fetches,
    /// which is bounded by the caller's own request concurrency and the HTTP
    /// connection pool — not by `max_entries`. It is deliberately not an
    /// accumulation cap (each concurrent fetch legitimately needs a gate); every
    /// gate is reclaimed the moment its fetch completes or is cancelled, so it
    /// cannot grow without bound the way the entry map could. The outer lock is a
    /// std mutex held only for the O(1) map lookup (never across an `await`); the
    /// per-URI [`tokio::sync::Mutex`] is what is held across the fetch.
    in_flight: StdMutex<HashMap<String, Arc<Mutex<()>>>>,
}

impl Cache {
    /// Returns an empty cache bounded to at most `max_entries` distinct URIs.
    /// A `max_entries` of `0` disables the bound (unbounded).
    pub(crate) fn new(max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            last_refresh: RwLock::new(HashMap::new()),
            max_entries,
            access_counter: AtomicU64::new(0),
            in_flight: StdMutex::new(HashMap::new()),
        }
    }

    /// Returns the next monotonic recency tick.
    fn next_tick(&self) -> u64 {
        self.access_counter.fetch_add(1, Ordering::Relaxed)
    }

    /// Returns the cached key set for `key` if present and unexpired (JWKS-005);
    /// returns `None` once the TTL has elapsed. A hit refreshes the entry's LRU
    /// recency so it is evicted last.
    pub(crate) async fn get(&self, key: &str) -> Option<JsonWebKeySet> {
        let entries = self.entries.read().await;
        let entry = entries.get(key)?;
        // A `None` expiry never elapses; otherwise the entry is fresh until then.
        if entry.expires_at.is_none_or(|at| Instant::now() < at) {
            // Refresh recency under the shared read lock via the atomic tick.
            entry.last_access.store(self.next_tick(), Ordering::Relaxed);
            Some(entry.key_set.clone())
        } else {
            None
        }
    }

    /// Stores `key_set` for `key`, expiring `ttl` from now, then evicts the
    /// least-recently-used entries until the cache is within its bound.
    pub(crate) async fn put(&self, key: String, key_set: JsonWebKeySet, ttl: Duration) {
        // `checked_add` guards against an overflow panic for a very large TTL
        // (e.g. `Duration::MAX`); `None` means the entry never expires.
        let expires_at = Instant::now().checked_add(ttl);
        let tick = self.next_tick();
        let mut entries = self.entries.write().await;
        entries.insert(
            key,
            CacheEntry {
                key_set,
                expires_at,
                last_access: AtomicU64::new(tick),
            },
        );
        let evicted = self.evict_lru(&mut entries);
        // Prune the refresh-cooldown sidecar for evicted keys while STILL holding
        // the `entries` write lock. If the lock were released first, a concurrent
        // `mark_refresh` on a just-evicted key could re-insert its cooldown record
        // in the window before this prune, and the prune would then delete that
        // fresh record — silently clearing a legitimately-refreshed URI's cooldown
        // and weakening the anti-hammering throttle. This is the only site that
        // holds both locks, and it always takes them entries -> last_refresh, so it
        // cannot deadlock with `mark_refresh`/`refresh_throttled` (which take only
        // `last_refresh`).
        if !evicted.is_empty() {
            let mut last_refresh = self.last_refresh.write().await;
            for key in &evicted {
                last_refresh.remove(key);
            }
        }
    }

    /// Evicts least-recently-used entries until `entries` is within
    /// `max_entries`, returning the evicted keys so the caller can prune sidecar
    /// state keyed by the same URIs. A `max_entries` of `0` is unbounded and
    /// evicts nothing. Runs under the caller's write lock.
    fn evict_lru(&self, entries: &mut HashMap<String, CacheEntry>) -> Vec<String> {
        let mut evicted = Vec::new();
        if self.max_entries == 0 {
            return evicted;
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
                    evicted.push(key);
                }
                None => break,
            }
        }
        evicted
    }

    /// Drops the cached entry for `key` so the next fetch re-fetches it from the
    /// provider (JWKS-006). The refresh-cooldown sidecar is intentionally left
    /// intact: `force_refresh` invalidates then immediately re-marks the URI.
    pub(crate) async fn invalidate(&self, key: &str) {
        self.entries.write().await.remove(key);
    }

    /// Records that `key` was just refreshed, starting its cooldown window, then
    /// caps the cooldown sidecar so it stays bounded.
    ///
    /// The cap is independent of entry eviction: `force_refresh` calls
    /// [`Cache::invalidate`] (which deliberately keeps the record so the cooldown
    /// still throttles repeated automatic refreshes) and only re-marks on
    /// success. If the re-fetch fails, the record has no backing entry, and
    /// entry-eviction — which only prunes records for keys still in `entries` —
    /// can never reclaim it. Capping here (evicting the least-recently-refreshed
    /// record) keeps the sidecar bounded under issuer/URI rotation regardless. A
    /// `max_entries` of `0` is unbounded, matching the entry map.
    pub(crate) async fn mark_refresh(&self, key: &str) {
        let mut last_refresh = self.last_refresh.write().await;
        last_refresh.insert(key.to_string(), Instant::now());
        if self.max_entries == 0 {
            return;
        }
        while last_refresh.len() > self.max_entries {
            let oldest = last_refresh
                .iter()
                .min_by_key(|(_, instant)| **instant)
                .map(|(key, _)| key.clone());
            match oldest {
                Some(key) => {
                    last_refresh.remove(&key);
                }
                None => break,
            }
        }
    }

    /// Reports whether `key` was refreshed less than `cooldown` ago, so another
    /// automatic refresh should be suppressed. A zero cooldown disables
    /// throttling. Mirrors `go/pkg/jwks` `cache.refreshThrottled`.
    pub(crate) async fn refresh_throttled(&self, key: &str, cooldown: Duration) -> bool {
        if cooldown.is_zero() {
            return false;
        }
        let last_refresh = self.last_refresh.read().await;
        match last_refresh.get(key) {
            Some(&last) => last.elapsed() < cooldown,
            None => false,
        }
    }

    /// Returns the single-flight gate for `key`, creating one if a fetch is not
    /// already in flight. Callers lock the returned gate across the fetch so
    /// concurrent misses for the same URI collapse to a single request.
    pub(crate) fn flight_gate(&self, key: &str) -> FlightGuard<'_> {
        let gate = {
            let mut in_flight = self.in_flight.lock().expect("in-flight gate map poisoned");
            in_flight
                .entry(key.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        FlightGuard {
            cache: self,
            key: key.to_string(),
            gate,
        }
    }

    /// Releases the single-flight gate for `key`, removing it from the map only
    /// if it is still the exact gate the caller held. Removing by identity is
    /// safe even while other waiters are still queued on the same `Arc`: they
    /// keep it alive through their own clone, and a later caller that finds the
    /// entry gone re-creates a fresh gate but observes the now-populated cache
    /// (so it never re-fetches).
    pub(crate) fn release_flight(&self, key: &str, gate: &Arc<Mutex<()>>) {
        let mut in_flight = self.in_flight.lock().expect("in-flight gate map poisoned");
        let is_same = in_flight
            .get(key)
            .is_some_and(|existing| Arc::ptr_eq(existing, gate));
        if is_same {
            in_flight.remove(key);
        }
    }

    /// Test-only: number of cached entries.
    #[cfg(test)]
    pub(crate) async fn entry_count(&self) -> usize {
        self.entries.read().await.len()
    }

    /// Test-only: number of refresh-cooldown sidecar records.
    #[cfg(test)]
    pub(crate) async fn refresh_record_count(&self) -> usize {
        self.last_refresh.read().await.len()
    }

    /// Test-only: number of live single-flight gates.
    #[cfg(test)]
    pub(crate) fn flight_gate_count(&self) -> usize {
        self.in_flight
            .lock()
            .expect("in-flight gate map poisoned")
            .len()
    }
}

/// RAII release for a single-flight gate. Holding the guard across the fetch
/// guarantees the gate is removed from `in_flight` when the guard drops —
/// including when the fetch future is cancelled (dropped) at an `await`. Without
/// it, `release_flight` ran only on the normal path, so an attacker steering
/// resolution at attacker-chosen URIs and disconnecting mid-fetch could strand
/// one gate per URI and grow the sidecar without bound (the very unbounded-growth
/// DoS the entry bound closes). Removal is by `Arc` identity, so the first holder
/// to drop reclaims the map slot and later holders (or a re-created gate) are
/// left untouched.
pub(crate) struct FlightGuard<'a> {
    cache: &'a Cache,
    key: String,
    gate: Arc<Mutex<()>>,
}

impl FlightGuard<'_> {
    /// The per-URI gate to lock across the fetch.
    pub(crate) fn gate(&self) -> &Arc<Mutex<()>> {
        &self.gate
    }
}

impl Drop for FlightGuard<'_> {
    fn drop(&mut self) {
        self.cache.release_flight(&self.key, &self.gate);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal key set value for cache-mechanics tests; contents are
    /// irrelevant here (LRU keys on the URI, not the payload).
    fn key_set() -> JsonWebKeySet {
        JsonWebKeySet { keys: Vec::new() }
    }

    const TTL: Duration = Duration::from_secs(60);

    // The cache never exceeds its configured cap no matter how many distinct
    // URIs are inserted (unbounded-growth DoS bound).
    #[tokio::test]
    async fn size_never_exceeds_cap() {
        let cache = Cache::new(3);
        for i in 0..25 {
            cache
                .put(format!("https://p/{i}/jwks"), key_set(), TTL)
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
        cache.put("a".to_string(), key_set(), TTL).await;
        cache.put("b".to_string(), key_set(), TTL).await;

        // Read "a" so it becomes more recently used than "b" (inserted after a).
        assert!(cache.get("a").await.is_some());

        // Inserting "c" overflows the cap; the LRU entry is now "b".
        cache.put("c".to_string(), key_set(), TTL).await;

        assert!(cache.get("a").await.is_some(), "recently-read a survives");
        assert!(cache.get("c").await.is_some(), "newest c present");
        assert!(
            cache.get("b").await.is_none(),
            "least-recently-used b evicted"
        );
        assert_eq!(cache.entry_count().await, 2);
    }

    // The refresh-cooldown sidecar is pruned in lockstep when its entry is
    // evicted, so it cannot outgrow the bounded entry map.
    #[tokio::test]
    async fn eviction_prunes_refresh_cooldown_sidecar() {
        let cache = Cache::new(2);
        cache.put("a".to_string(), key_set(), TTL).await;
        cache.mark_refresh("a").await;
        cache.put("b".to_string(), key_set(), TTL).await;
        cache.mark_refresh("b").await;
        assert_eq!(cache.refresh_record_count().await, 2);
        assert!(cache.refresh_throttled("a", TTL).await);

        // "a" is least-recently-used (never read; "b" inserted after it).
        // Inserting "c" evicts "a" and must prune a's cooldown record too.
        cache.put("c".to_string(), key_set(), TTL).await;

        assert!(cache.get("a").await.is_none(), "a evicted");
        assert_eq!(
            cache.refresh_record_count().await,
            1,
            "sidecar record for evicted a pruned"
        );
        assert!(
            cache.refresh_throttled("b", TTL).await,
            "b's cooldown intact"
        );
        assert!(
            !cache.refresh_throttled("a", TTL).await,
            "a's cooldown pruned, no longer throttled"
        );
    }

    // A cap of 0 disables the bound entirely (backward-compat unbounded mode).
    #[tokio::test]
    async fn zero_cap_is_unbounded() {
        let cache = Cache::new(0);
        for i in 0..100 {
            cache.put(format!("uri-{i}"), key_set(), TTL).await;
        }
        assert_eq!(cache.entry_count().await, 100, "cap 0 evicts nothing");
    }

    // TTL expiry is unchanged by the LRU layer: an expired entry is not served.
    #[tokio::test]
    async fn expired_entry_is_not_served() {
        let cache = Cache::new(8);
        cache
            .put("a".to_string(), key_set(), Duration::from_millis(10))
            .await;
        assert!(cache.get("a").await.is_some(), "fresh before TTL");
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(cache.get("a").await.is_none(), "expired after TTL");
    }

    // A very large TTL must not overflow `Instant`; the entry never expires.
    #[tokio::test]
    async fn max_ttl_never_expires() {
        let cache = Cache::new(8);
        cache.put("a".to_string(), key_set(), Duration::MAX).await;
        assert!(cache.get("a").await.is_some(), "max-ttl entry stays fresh");
    }

    // Releasing a single-flight gate removes it from the map (no unbounded
    // growth), and only the holder of the current gate removes it.
    #[tokio::test]
    async fn flight_gate_is_released() {
        let cache = Cache::new(8);
        let guard = cache.flight_gate("u");
        assert_eq!(cache.flight_gate_count(), 1);
        // A second request for the same URI shares the same underlying gate.
        let guard2 = cache.flight_gate("u");
        assert!(Arc::ptr_eq(guard.gate(), guard2.gate()));
        assert_eq!(cache.flight_gate_count(), 1);
        // Dropping a holder releases the gate via RAII; removal is by identity so
        // it happens exactly once even while another holder is still alive.
        drop(guard);
        assert_eq!(
            cache.flight_gate_count(),
            0,
            "gate pruned when a holder drops"
        );
        drop(guard2);
        assert_eq!(cache.flight_gate_count(), 0);
    }

    // A failed force_refresh leaves a cooldown record with no backing entry that
    // entry-eviction can never reclaim; mark_refresh must cap the sidecar so such
    // records cannot accumulate without bound under issuer/URI rotation. Records
    // are only ever created by mark_refresh, so capping there bounds the map.
    #[tokio::test]
    async fn refresh_sidecar_is_bounded_independently() {
        let cache = Cache::new(3);
        for i in 0..50 {
            cache.mark_refresh(&format!("https://p/{i}/jwks")).await;
            assert!(
                cache.refresh_record_count().await <= 3,
                "cooldown sidecar exceeded cap after marking entry {i}"
            );
        }
    }
}
