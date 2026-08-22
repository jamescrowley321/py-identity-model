package discovery

import (
	"container/list"
	"context"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// cacheEntry is a cached configuration with its expiry instant. key duplicates
// the issuer URL the entry is stored under so an LRU eviction can drop it from
// the lookup map by key.
type cacheEntry struct {
	key       string
	cfg       *ProviderConfiguration
	expiresAt time.Time
}

// cache is a bounded, TTL cache for discovery documents keyed by issuer URL.
// Concurrent fetches for the same issuer are deduplicated via singleflight so
// only one HTTP request is made when the cache is empty or expired.
//
// The cache is bounded by a max-entries LRU: without a bound it grows one entry
// per distinct issuer forever, so a caller driven to resolve many distinct
// issuers (a multi-tenant gateway, an attacker-supplied issuer header) leaks
// memory unbounded (a DoS). Recency is tracked in order — a read hit or a store
// moves the entry to the front, and eviction pops the back — so the entry
// evicted under pressure is the least recently *used*, not merely the least
// recently inserted. FIFO would let an attacker reading distinct issuers in
// insertion order evict a legitimately hot entry.
type cache struct {
	mu sync.RWMutex

	// entries maps issuer URL -> its element in order; each element's Value is a
	// *cacheEntry. The single map+list pair gives O(1) lookup, recency promotion
	// and eviction, all serialized by mu.
	entries map[string]*list.Element

	// order tracks access recency: most-recently-used at the front,
	// least-recently-used at the back. Eviction removes from the back.
	order *list.List

	group singleflight.Group

	// now returns the current time; overridable in tests to drive TTL expiry
	// deterministically (DISC-005).
	now func() time.Time
}

// globalCache backs the package-level [FetchConfiguration].
var globalCache = newCache()

// newCache returns an empty cache using the wall clock.
func newCache() *cache {
	return &cache{
		entries: make(map[string]*list.Element),
		order:   list.New(),
		now:     time.Now,
	}
}

// lookup returns the cached configuration for key if present and unexpired,
// promoting the entry to most-recently-used on a hit. Promotion mutates the
// recency list, so this takes the exclusive lock rather than a read lock; the
// critical section is a map probe and an O(1) list move. An expired entry is
// neither promoted nor removed here — it is overwritten by the next store or
// evicted under pressure.
func (c *cache) lookup(key string) (*ProviderConfiguration, bool) {
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
	return entry.cfg, true
}

// store records cfg for key with the supplied TTL, marks the entry
// most-recently-used, and enforces the max-entries bound. A maxEntries <= 0
// disables the bound (unbounded) — the backward-compatible escape hatch.
func (c *cache) store(key string, cfg *ProviderConfiguration, ttl time.Duration, maxEntries int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := &cacheEntry{key: key, cfg: cfg, expiresAt: c.now().Add(ttl)}
	if elem, ok := c.entries[key]; ok {
		elem.Value = entry
		c.order.MoveToFront(elem)
	} else {
		c.entries[key] = c.order.PushFront(entry)
	}
	c.evictLocked(maxEntries)
}

// evictLocked drops least-recently-used entries until at most maxEntries remain.
// It must be called with mu held. A maxEntries <= 0 disables eviction.
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
	}
}

// clear drops every cached configuration.
func (c *cache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*list.Element)
	c.order = list.New()
}

// fetch returns the cached configuration for issuerURL or fetches it, caching
// the result. Concurrent misses for the same issuer collapse to one fetch.
//
// Concurrency semantics: when several callers miss the cache simultaneously,
// only the first triggers the HTTP request and the rest wait on its result.
// The shared fetch runs on a context detached from any single caller (via
// [context.WithoutCancel]), so one caller cancelling or timing out cannot
// poison the request other callers depend on; each caller still observes its
// own context cancellation through the select below. Because the shared fetch
// is detached, a deadline carried only on a caller's context does not bound the
// underlying request (the caller still unblocks at its deadline, but the fetch
// runs to the configured [WithTimeout] or the default request timeout). The
// timeout, cache TTL and max-entries bound applied to the shared fetch are those
// of the caller that wins the flight (first-wins) — callers needing distinct
// timeouts should not rely on the shared cache for that guarantee.
func (c *cache) fetch(ctx context.Context, issuerURL string, cfg *config) (*ProviderConfiguration, error) {
	// DISC-004: serve a fresh cache entry without any HTTP request.
	if doc, ok := c.lookup(issuerURL); ok {
		return doc, nil
	}

	// Singleflight collapses concurrent misses into one in-flight request.
	// DoChan (not Do) lets each caller honour its own context independently.
	ch := c.group.DoChan(issuerURL, func() (interface{}, error) {
		// Re-check under the flight in case another goroutine just populated
		// the cache (DISC-005 boundary).
		if doc, ok := c.lookup(issuerURL); ok {
			return doc, nil
		}
		// Detach from the winning caller's context so its cancellation does
		// not abort the fetch the other waiters share. fetchAndValidate still
		// bounds the request with the configured (or default) timeout.
		doc, err := fetchAndValidate(context.WithoutCancel(ctx), issuerURL, cfg)
		if err != nil {
			return nil, err
		}
		// Only successful fetches are cached.
		c.store(issuerURL, doc, cfg.cacheTTL, cfg.maxEntries)
		return doc, nil
	})

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		if res.Err != nil {
			return nil, res.Err
		}
		return res.Val.(*ProviderConfiguration), nil
	}
}
