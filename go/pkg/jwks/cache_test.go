package jwks

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// The max-entries LRU bound is exercised here directly against the cache methods
// (store/lookup/evict) so the recency and sidecar-pruning behaviour is asserted
// without the noise of HTTP plumbing; TestFetchKeySet_MaxCacheEntries_EvictsLRU
// then proves the same bound flows through the public FetchKeySet path.

// keysFor builds a minimal one-key set stored under a synthetic URI. store and
// lookup do no key validation, so a kid-only key is enough to identify an entry.
func keysFor(id string) []JSONWebKey {
	return []JSONWebKey{{Kid: id}}
}

// cacheLen returns the number of live entries without promoting any of them
// (lookup would bump an entry's recency and perturb the LRU order).
func cacheLen(c *cache) int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// cacheHas reports whether key is present without promoting it.
func cacheHas(c *cache, key string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.entries[key]
	return ok
}

// sidecarHas reports whether the refresh-cooldown sidecar holds key.
func sidecarHas(c *cache, key string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.lastRefresh[key]
	return ok
}

// sidecarLen returns the number of refresh-cooldown records.
func sidecarLen(c *cache) int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.lastRefresh)
}

// (a) The number of cached entries never exceeds the configured cap, regardless
// of how many distinct URIs are inserted.
func TestCache_SizeNeverExceedsCap(t *testing.T) {
	for _, limit := range []int{1, 2, 8, 64} {
		t.Run(fmt.Sprintf("cap=%d", limit), func(t *testing.T) {
			c := newCache()
			for i := 0; i < limit*4; i++ {
				key := fmt.Sprintf("https://issuer.example/%d/jwks", i)
				c.store(key, keysFor(key), time.Hour, limit)
				if got := cacheLen(c); got > limit {
					t.Fatalf("after %d inserts, size = %d, want <= %d", i+1, got, limit)
				}
			}
			if got := cacheLen(c); got != limit {
				t.Errorf("final size = %d, want %d (cap saturated)", got, limit)
			}
		})
	}
}

// (b) Eviction is least-recently-used: the entry evicted under pressure is the
// one used longest ago, and a read hit refreshes recency so a would-be victim
// survives. Each case runs a script of store("s:key") / read("r:key") ops
// against a cap-2 cache and asserts exactly which keys survive.
func TestCache_LRUEvictionOrder(t *testing.T) {
	const limit = 2
	tests := []struct {
		name     string
		ops      []string
		survives []string
		evicted  []string
	}{
		{
			name:     "insertion order evicts oldest",
			ops:      []string{"s:A", "s:B", "s:C"},
			survives: []string{"B", "C"},
			evicted:  []string{"A"},
		},
		{
			name:     "read refreshes recency so oldest survives",
			ops:      []string{"s:A", "s:B", "r:A", "s:C"},
			survives: []string{"A", "C"},
			evicted:  []string{"B"},
		},
		{
			name:     "restore promotes on write so it is not the next victim",
			ops:      []string{"s:A", "s:B", "s:A", "s:C"},
			survives: []string{"A", "C"},
			evicted:  []string{"B"},
		},
		{
			name:     "read miss on evicted key does not promote it back",
			ops:      []string{"s:A", "s:B", "s:C", "r:A"},
			survives: []string{"B", "C"},
			evicted:  []string{"A"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newCache()
			for _, op := range tt.ops {
				action, id := op[:1], op[2:]
				switch action {
				case "s":
					c.store(id, keysFor(id), time.Hour, limit)
				case "r":
					c.lookup(id)
				default:
					t.Fatalf("bad op %q", op)
				}
			}
			if got := cacheLen(c); got != limit {
				t.Fatalf("size = %d, want %d", got, limit)
			}
			for _, id := range tt.survives {
				if !cacheHas(c, id) {
					t.Errorf("%q was evicted, want retained", id)
				}
			}
			for _, id := range tt.evicted {
				if cacheHas(c, id) {
					t.Errorf("%q was retained, want evicted", id)
				}
			}
		})
	}
}

// (c) The refresh-cooldown sidecar is pruned in lockstep: when a jwks_uri is
// evicted from the cache, its lastRefresh record is deleted too, so the sidecar
// stays bounded alongside entries rather than leaking one record per distinct
// URI forever.
func TestCache_EvictionPrunesRefreshSidecar(t *testing.T) {
	const limit = 2
	c := newCache()

	// A and B occupy the cache and both have cooldown records.
	c.store("A", keysFor("A"), time.Hour, limit)
	c.markRefresh("A", limit)
	c.store("B", keysFor("B"), time.Hour, limit)
	c.markRefresh("B", limit)
	if sidecarLen(c) != 2 {
		t.Fatalf("precondition: sidecar len = %d, want 2", sidecarLen(c))
	}

	// Inserting C evicts A (the LRU). Its sidecar record must go with it.
	c.store("C", keysFor("C"), time.Hour, limit)
	c.markRefresh("C", limit)

	if cacheHas(c, "A") {
		t.Error("A should have been evicted from the cache")
	}
	if sidecarHas(c, "A") {
		t.Error("A's refresh-cooldown record leaked after eviction (sidecar not pruned)")
	}
	if !sidecarHas(c, "B") || !sidecarHas(c, "C") {
		t.Error("B and C cooldown records should survive")
	}
	if got := sidecarLen(c); got != limit {
		t.Errorf("sidecar len = %d, want %d (bounded with the cache)", got, limit)
	}

	// An evicted URI is no longer throttled, since its cooldown record is gone —
	// the pruning is observable through the public refresh-throttle gate too.
	if c.refreshThrottled("A", time.Minute) {
		t.Error("evicted URI A should not be throttled (its cooldown record was pruned)")
	}
}

// A failed ForceRefresh leaves a cooldown record with no backing entry that LRU
// eviction can never reclaim (it only prunes records for keys still cached).
// markRefresh must therefore cap lastRefresh independently, so such records
// cannot accumulate without bound under issuer/URI rotation. Records are only
// ever created by markRefresh, so capping there bounds the map regardless.
func TestCache_MarkRefreshBoundsSidecarIndependently(t *testing.T) {
	const limit = 3
	c := newCache()
	for i := 0; i < 50; i++ {
		c.markRefresh(fmt.Sprintf("https://p/%d/jwks", i), limit)
		if got := sidecarLen(c); got > limit {
			t.Fatalf("cooldown sidecar exceeded cap: got %d after marking entry %d, want <= %d", got, i, limit)
		}
	}
}

// (d) A cap of 0 or a negative value disables the bound entirely (the
// backward-compatible unbounded escape hatch): no entry is ever evicted.
func TestCache_UnboundedWhenCapNonPositive(t *testing.T) {
	for _, limit := range []int{0, -1, -1000} {
		t.Run(fmt.Sprintf("cap=%d", limit), func(t *testing.T) {
			c := newCache()
			const n = 500
			for i := 0; i < n; i++ {
				key := strconv.Itoa(i)
				c.store(key, keysFor(key), time.Hour, limit)
			}
			if got := cacheLen(c); got != n {
				t.Fatalf("size = %d, want %d (no eviction when cap<=0)", got, n)
			}
			// The very first key inserted is still present.
			if !cacheHas(c, "0") {
				t.Error("oldest entry evicted despite unbounded cap")
			}
		})
	}
}

// (e) The bound must not regress TTL expiry: a bounded cache still expires
// entries by TTL, and an expired entry is not served (nor promoted) on lookup.
func TestCache_BoundDoesNotRegressTTL(t *testing.T) {
	c := newCache()
	base := time.Unix(1_700_000_000, 0)
	var clock atomic.Int64
	clock.Store(base.UnixNano())
	c.now = func() time.Time { return time.Unix(0, clock.Load()) }

	c.store("A", keysFor("A"), time.Minute, 8)

	// Within TTL: hit.
	if _, ok := c.lookup("A"); !ok {
		t.Fatal("within TTL: lookup(A) = miss, want hit")
	}
	// Past TTL: miss, even though the entry still occupies a slot.
	clock.Store(base.Add(2 * time.Minute).UnixNano())
	if _, ok := c.lookup("A"); ok {
		t.Error("past TTL: lookup(A) = hit, want miss (TTL regressed)")
	}
}

// maxCacheEntriesFromEnv / newConfig: the JWKS_CACHE_MAX_ENTRIES knob resolves
// the default bound, garbage falls back to the default rather than silently
// unbounding the cache, and WithMaxCacheEntries overrides the env value.
func TestMaxCacheEntriesConfig(t *testing.T) {
	envCases := []struct {
		raw  string // "" is treated identically to unset
		want int
	}{
		{"", defaultMaxCacheEntries},
		{"3", 3},
		{"128", 128},
		{"  7  ", 7},
		{"0", 0},                       // explicit unbounded escape hatch
		{"-5", defaultMaxCacheEntries}, // negative -> default (parity with Rust/Python; a typo cannot silently unbound)
		{"abc", defaultMaxCacheEntries},
		{"12.5", defaultMaxCacheEntries},
		{"   ", defaultMaxCacheEntries},
	}
	for _, tc := range envCases {
		t.Run("env="+strconv.Quote(tc.raw), func(t *testing.T) {
			t.Setenv(maxCacheEntriesEnv, tc.raw)
			if got := maxCacheEntriesFromEnv(); got != tc.want {
				t.Errorf("maxCacheEntriesFromEnv() = %d, want %d", got, tc.want)
			}
			if got := newConfig().maxEntries; got != tc.want {
				t.Errorf("newConfig().maxEntries = %d, want %d", got, tc.want)
			}
		})
	}

	// WithMaxCacheEntries wins over the environment default.
	t.Run("option overrides env", func(t *testing.T) {
		t.Setenv(maxCacheEntriesEnv, "3")
		if got := newConfig(WithMaxCacheEntries(9)).maxEntries; got != 9 {
			t.Errorf("maxEntries = %d, want 9 (option overrides env)", got)
		}
		// 0 is the unbounded escape hatch and must survive newConfig unclamped.
		if got := newConfig(WithMaxCacheEntries(0)).maxEntries; got != 0 {
			t.Errorf("maxEntries = %d, want 0 (unbounded escape hatch preserved)", got)
		}
		// A negative option value is invalid and falls back to the default,
		// matching the env-var semantics (a mis-parsed config cannot unbound).
		if got := newConfig(WithMaxCacheEntries(-1)).maxEntries; got != defaultMaxCacheEntries {
			t.Errorf("maxEntries = %d, want %d (negative option -> default)", got, defaultMaxCacheEntries)
		}
	})
}

// End-to-end: the bound flows through FetchKeySet. With a cap of 2, fetching
// three distinct URIs evicts the least-recently-used one, so re-fetching it
// re-hits the network while the most-recently-used URI is still served from
// cache. This proves WithMaxCacheEntries is wired into the public API and that
// singleflight-backed fetch/store still honour the bound.
func TestFetchKeySet_MaxCacheEntries_EvictsLRU(t *testing.T) {
	freshCache(t)

	newKeyServer := func(kid string) (string, *int32) {
		var hits int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&hits, 1)
			_, _ = w.Write(keySetJSON(rsaKeyJSON(kid)))
		}))
		t.Cleanup(srv.Close)
		return srv.URL, &hits
	}

	urlA, hitsA := newKeyServer("a")
	urlB, _ := newKeyServer("b") // B's fate depends on the re-fetch sequence; not asserted.
	urlC, hitsC := newKeyServer("c")

	opts := []Option{WithInsecureAllowHTTP(), WithMaxCacheEntries(2)}
	for _, u := range []string{urlA, urlB, urlC} {
		if _, err := FetchKeySet(context.Background(), u, opts...); err != nil {
			t.Fatalf("FetchKeySet(%s): %v", u, err)
		}
	}
	// A was the least-recently-used of {A,B,C} and is evicted by C's insert.
	if got := atomic.LoadInt32(hitsA); got != 1 {
		t.Fatalf("precondition: A fetched %d times, want 1", got)
	}

	// Re-fetching A misses (evicted) → one more network hit.
	if _, err := FetchKeySet(context.Background(), urlA, opts...); err != nil {
		t.Fatalf("re-fetch A: %v", err)
	}
	if got := atomic.LoadInt32(hitsA); got != 2 {
		t.Errorf("A hits = %d, want 2 (evicted then re-fetched)", got)
	}

	// C was most-recently-used and is still cached → served without a network hit.
	if _, err := FetchKeySet(context.Background(), urlC, opts...); err != nil {
		t.Fatalf("re-fetch C: %v", err)
	}
	if got := atomic.LoadInt32(hitsC); got != 1 {
		t.Errorf("C hits = %d, want 1 (still cached)", got)
	}
}
