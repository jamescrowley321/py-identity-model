# identity-model (Go)

Go implementation of the [identity-model](../README.md) OIDC/OAuth2 client library.

- **Module:** `github.com/jamescrowley321/py-identity-model/go`
- **Minimum Go:** 1.26
- **Install:** `go get github.com/jamescrowley321/py-identity-model/go`

> **Imported from `identity-model` (CONS-1).** This Go binding was merged into
> `py-identity-model` as part of the polyglot consolidation epic. The module
> path above is **interim** and will change again at the repo rename (CONS-3);
> there are no external consumers, so the churn is accepted. See `CHANGELOG.md`.

## Package Layout

| Package | Purpose | Spec |
|---------|---------|------|
| `pkg/discovery` | OIDC Discovery client | OIDC Discovery 1.0 |
| `pkg/jwks` | JWKS fetch + key resolution | RFC 7517 / 7518 |
| `pkg/jwt` | JWT signature + claims validation | RFC 7519 / 7515 |
| `pkg/token` | Client credentials, auth code, PKCE | RFC 6749 / 7636 |
| `pkg/introspection` | Token introspection client | RFC 7662 |
| `pkg/revocation` | Token revocation client | RFC 7009 |
| `pkg/dpop` | DPoP proof creation + verification | RFC 9449 |
| `pkg/userinfo` | UserInfo endpoint client | OIDC Core 1.0 §5.3 |
| `internal/` | Shared non-exported utilities | — |

## Design Conventions

- HTTP via `net/http` stdlib; `sync.Pool` for client reuse.
- Functional options for configuration: `WithTimeout()`, `WithCacheTTL()`, `WithHTTPClient()`.
- `singleflight` to deduplicate concurrent discovery / JWKS fetches.
- JOSE handling via `go-jose/v4`.

## Getting Started

```bash
go build ./...
go vet ./...
go test ./...
go run ./examples/hello
```

Integration tests (build tag `integration`) run against the shared provider in [`../infra`](../infra).

> **Status:** Imported from `identity-model` (CONS-1.1); `go build/vet/test ./...` green. The cross-language conformance vectors (`spec/`) land in CONS-1.3 — until then the fixture-driven tests skip cleanly. See [`CHANGELOG.md`](CHANGELOG.md).
