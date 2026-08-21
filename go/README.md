# identity-model (Go)

A native Go library for OpenID Connect and OAuth 2.0 clients: discovery, JWKS
retrieval and key resolution, JWT validation, and the token, introspection,
revocation, DPoP, and UserInfo endpoints.

- **Module:** `github.com/jamescrowley321/py-identity-model/go`
- **Minimum Go:** 1.26
- **Install:** `go get github.com/jamescrowley321/py-identity-model/go`

## Packages

| Package | Purpose | Spec |
|---------|---------|------|
| `pkg/discovery` | OIDC Discovery client | OIDC Discovery 1.0 |
| `pkg/jwks` | JWKS fetch + key resolution | RFC 7517 / 7518 |
| `pkg/jwt` | JWT signature + claims validation | RFC 7519 / 7515 |
| `pkg/token` | Client credentials, authorization code, PKCE | RFC 6749 / 7636 |
| `pkg/introspection` | Token introspection client | RFC 7662 |
| `pkg/revocation` | Token revocation client | RFC 7009 |
| `pkg/dpop` | DPoP proof creation + verification | RFC 9449 |
| `pkg/userinfo` | UserInfo endpoint client | OIDC Core 1.0 §5.3 |

## Design

- HTTP via the `net/http` standard library; `sync.Pool` for client reuse.
- Functional options for configuration: `WithTimeout()`, `WithCacheTTL()`, `WithHTTPClient()`.
- `singleflight` deduplicates concurrent discovery / JWKS fetches.
- JOSE handling via `go-jose/v4`.

## Getting started

```bash
go build ./...
go test ./...
go run ./examples/hello
```

Integration tests use the `integration` build tag and run against the shared
providers in [`../infra`](../infra); start them with `make infra-up` from the
repo root. The env-free default profile targets node-oidc-provider on `:9010`;
source `.env.identityserver` to run the same tests against IdentityServer.

Behavioral parity with the Python and Rust libraries is enforced by the
cross-language conformance vectors in [`../spec`](../spec), which the
`internal/conformance` runner executes.
