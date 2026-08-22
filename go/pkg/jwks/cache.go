package jwks

import (
	"container/list"
	"context"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// cacheEntry is a cached key set with its expiry instant. The keys slice (not a
// *JSONWebKeySet handle) is cached so that a handle's ForceRefresh can swap in a
// fresh slice without the cache holding a self-referential pointer back to the
// handle. key duplicates the jwks_uri the entry is stored under so an LRU
// eviction can prune the sidecar refresh-cooldown record keyed by the same URI.
type cacheEntry struct {
	key       string
	keys      []JSONWebKey
	expiresAt time.Time
}

// cache is a bounded, TTL cache for JWK Sets keyed by jwks_uri. Concurrent
// fetches for the same URI are deduplicated via singleflight so only one HTTP
// request is made when the cache is empty or expired.
//
// The cache is bounded by a max-entries LRU: without a bound it grows one entry
// per distinct jwks_uri forever, so a caller driven to resolve tokens against
// many distinct issuers (a multi-tenant gateway, an attacker-supplied issuer
// header) leaks memory unbounded (a DoS). Recency is tracked in order — a read
// hit or a store moves the entry to the front, and eviction pops the back — so
// the entry evicted under pressure is the least recently *used*, not merely the
// least recently inserted. FIFO would let an attacker reading distinct URIs in
// insertion order evict a legitimately hot entry.
type cache struct {
	mu sync.RWMutex

	// entries maps jwks_uri -> its element in order; each element's Value is a
	// *cacheEntry. The single map+list pair gives O(1) lookup, recency promotion
	// and eviction, all serialized by mu.
	entries map[string]*list.Element

	// order tracks access recency: most-recently-used at the front,
	// least-recently-used at the back. Eviction removes from the back.
	order *list.List

	group singleflight.Group

	// lastRefresh records when each jwks_uri was last refreshed, throttling
	// automatic refreshes so an unknown kid cannot drive unbounded re-fetches
	// (see [cache.refreshThrottled]). It is a sidecar keyed by the same jwks_uri
	// as entries; an LRU eviction prunes the evicted URI's record here in
	// lockstep (see [cache.evictLocked]) so it stays bounded alongside entries.
	lastRefresh map[string]time.Time

	// now returns the current time; overridable in tests to drive TTL expiry
	// deterministically (JWKS-005).
	now func() time.Time
}

// globalCache backs the package-level [FetchKeySet].
var globalCache = newCache()

// newCache returns an empty cache using the wall clock.
func newCache() *cache {
	return &cache{
		entries:     make(map[string]*list.Element),
		order:       list.New(),
		lastRefresh: make(map[string]time.Time),
		now:         time.Now,
	}
}

// markRefresh records that key was just refreshed, starting its cooldown window.
func (c *cache) markRefresh(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastRefresh[key] = c.now()
}

// refreshThrottled reports whether key was refreshed less than cooldown ago, so
// another automatic refresh should be suppressed. A non-positive cooldown
// disables throttling.
func (c *cache) refreshThrottled(key string, cooldown time.Duration) bool {
	if cooldown <= 0 {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	last, ok := c.lastRefresh[key]
	if !ok {
		return false
	}
	return c.now().Sub(last) < cooldown
}

// lookup returns the cached keys for key if present and unexpired, promoting the
// entry to most-recently-used on a hit. Promotion mutates the recency list, so
// this takes the exclusive lock rather than a read lock; the critical section is
// a map probe and an O(1) list move. An expired entry is neither promoted nor
// removed here — it is overwritten by the next store or evicted under pressure.
func (c *cache) lookup(key string) ([]JSONWebKey, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	elem, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	entry := elem.Value.(*cacheEntry)
	if !c.now().Before(entry.expiresAt) {
		return nil, false
	}
	c.order.MoveToFront(elem)
	return entry.keys, true
}

// store records keys for key with the supplied TTL, marks the entry
// most-recently-used, and enforces the max-entries bound. A maxEntries <= 0
// disables the bound (unbounded) — the backward-compatible escape hatch.
func (c *cache) store(key string, keys []JSONWebKey, ttl time.Duration, maxEntries int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := &cacheEntry{key: key, keys: keys, expiresAt: c.now().Add(ttl)}
	if elem, ok := c.entries[key]; ok {
		elem.Value = entry
		c.order.MoveToFront(elem)
	} else {
		c.entries[key] = c.order.PushFront(entry)
	}
	c.evictLocked(maxEntries)
}

// evictLocked drops least-recently-used entries until at most maxEntries remain.
// It must be called with mu held. A maxEntries <= 0 disables eviction. Each
// evicted jwks_uri's sidecar refresh-cooldown record is deleted in lockstep so
// lastRefresh cannot grow unbounded even though entries is bounded.
func (c *cache) evictLocked(maxEntries int) {
	if maxEntries <= 0 {
		return
	}
	for c.order.Len() > maxEntries {
		back := c.order.Back()
		if back == nil {
			return
		}
		evicted := c.order.Remove(back).(*cacheEntry)
		delete(c.entries, evicted.key)
		delete(c.lastRefresh, evicted.key)
	}
}

// invalidate drops any cached entry for key so the next fetch re-requests it.
// It backs ForceRefresh (JWKS-006). The refresh-cooldown record is left intact:
// ForceRefresh re-establishes it via markRefresh after the re-fetch succeeds.
func (c *cache) invalidate(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if elem, ok := c.entries[key]; ok {
		c.order.Remove(elem)
		delete(c.entries, key)
	}
}

// clear drops every cached entry and refresh-cooldown record.
func (c *cache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*list.Element)
	c.order = list.New()
	c.lastRefresh = make(map[string]time.Time)
}

// fetch returns the cached keys for jwksURI or fetches them, caching the
// result. Concurrent misses for the same URI collapse to one fetch.
//
// Concurrency semantics mirror the discovery client: when several callers miss
// the cache simultaneously, only the first triggers the HTTP request and the
// rest wait on its result. The shared fetch runs on a context detached from any
// single caller (via [context.WithoutCancel]) so one caller cancelling or
// timing out cannot poison the request other callers depend on; each caller
// still observes its own context cancellation through the select below. The
// timeout, cache TTL and max-entries bound applied to the shared fetch are those
// of the caller that wins the flight (first-wins).
func (c *cache) fetch(ctx context.Context, jwksURI string, cfg *config) ([]JSONWebKey, error) {
	// JWKS-005: serve a fresh cache entry without any HTTP request. Return a
	// deep copy so the caller's handle cannot mutate the cached master copy.
	if keys, ok := c.lookup(jwksURI); ok {
		return cloneKeys(keys), nil
	}

	// Singleflight collapses concurrent misses into one in-flight request.
	// DoChan (not Do) lets each caller honour its own context independently.
	ch := c.group.DoChan(jwksURI, func() (interface{}, error) {
		// Re-check under the flight in case another goroutine just populated
		// the cache.
		if keys, ok := c.lookup(jwksURI); ok {
			return keys, nil
		}
		// Detach from the winning caller's context so its cancellation does
		// not abort the fetch the other waiters share. fetchAndParse still
		// bounds the request with the configured (or default) timeout.
		keys, err := fetchAndParse(context.WithoutCancel(ctx), jwksURI, cfg)
		if err != nil {
			return nil, err
		}
		// Only successful fetches are cached.
		c.store(jwksURI, keys, cfg.cacheTTL, cfg.maxEntries)
		return keys, nil
	})

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		if res.Err != nil {
			return nil, res.Err
		}
		// Each waiter receives the same shared result value; hand back a deep
		// copy so concurrent callers never alias one another's (or the cache's)
		// key set.
		return cloneKeys(res.Val.([]JSONWebKey)), nil
	}
}
