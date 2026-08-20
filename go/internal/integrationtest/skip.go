package integrationtest

import (
	"os"
	"testing"
)

// SkipUnreachable skips t when the live provider cannot be reached — unless
// TEST_REQUIRE_LIVE=1, in which case it fails instead. CI sets the variable in
// the legs that just booted the fixture, so a URL/profile drift between the
// in-code defaults and infra/docker-compose.yml turns the whole leg red rather
// than silently green-skipping every test (mechanical-gate rule, CONS-1.4
// review). Capability/profile skips (e.g. an unset TEST_OPAQUE_CLIENT_ID) are
// deliberately NOT routed through this: those are legitimate per-provider
// gaps, not infrastructure failures.
func SkipUnreachable(t testing.TB, format string, args ...any) {
	t.Helper()
	if os.Getenv("TEST_REQUIRE_LIVE") == "1" {
		t.Fatalf("TEST_REQUIRE_LIVE=1 but "+format, args...)
	}
	t.Skipf(format, args...)
}
