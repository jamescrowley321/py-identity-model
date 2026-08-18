package introspection

import (
	"os"
	"path/filepath"
	"testing"
)

// requireSpec skips the calling test when the shared spec/ test-fixture tree is
// absent. That tree is imported in CONS-1.3; until then the fixture-driven tests
// (which replay spec/test-fixtures/introspection) skip cleanly, while pure unit
// tests that never read fixtures — the response_test.go Audience cases — still
// execute and keep their regression coverage.
//
// Call this from the fixture loader (fixture, reached in the test goroutine) so
// the skip unwinds the whole test. A t.Skip fired inside an httptest handler
// goroutine would unwind only that goroutine, not the test, so any test that
// reads a fixture solely inside a handler (TestIntrospect_DiscoveryEndpointResolution)
// must call requireSpec from the top of its body instead. Once spec/ lands the
// guard is a no-op and every test runs for real.
func requireSpec(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(filepath.Join("..", "..", "..", "spec", "test-fixtures")); err != nil {
		t.Skip("spec/ test fixtures absent (imported in CONS-1.3)")
	}
}
