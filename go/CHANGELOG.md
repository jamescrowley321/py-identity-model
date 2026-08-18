# Changelog — Go binding

All notable changes to the Go binding (`go/`) are documented here. This file is
independent of the repository-root `CHANGELOG.md`, which is owned by
python-semantic-release and tracks the Python package only.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/).

## Unreleased

### Added

- **Imported the Go binding into `py-identity-model` under `go/`** as part of the
  polyglot consolidation epic (CONS-1, story CONS-1.1). The tree was previously
  developed in the standalone `identity-model` repository and is brought in as a
  plain copy (its history is expendable — never tagged or released).

### Changed

- **Module path rewritten** from `github.com/jamescrowley321/identity-model/go`
  to `github.com/jamescrowley321/py-identity-model/go`. This path is **interim**:
  it changes again when the repository is renamed in CONS-3. There are no external
  consumers, so the churn is accepted.

### Notes

- **`spec/` test fixtures are not yet present.** The shared conformance vector
  tree (`spec/test-fixtures`, `spec/conformance`) lands in story CONS-1.3. Until
  then, the fixture-driven tests skip cleanly while the pure unit tests that read
  no fixtures still run and keep their regression coverage. The skip is scoped to
  the fixture reads: most packages use a per-package `TestMain` guard (all their
  non-integration tests are fixture-driven); `pkg/token` and `pkg/introspection`
  additionally carry non-fixture unit tests (`pkce_test.go`, the literal-body
  `token_test.go` cases, `response_test.go`), so those two guard at the fixture
  loader (and, for the one test that reads fixtures only inside an httptest
  handler goroutine, at the top of the test body). The conformance suite uses an
  in-test guard. `go build ./...`, `go vet ./...`, and `go test ./...` are all
  green. Once `spec/` is imported the guards become no-ops and every vector
  executes for real.
- **Integration tests** (`*_integration_test.go`, `//go:build integration`) remain
  excluded from the default `go test ./...` run; they require the consolidated
  `/infra` stack that lands in story CONS-1.4.
