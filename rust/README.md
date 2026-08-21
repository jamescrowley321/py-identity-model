# identity-model (Rust)

A native Rust library for OpenID Connect and OAuth 2.0 clients: discovery,
JWKS retrieval and key resolution, JWT validation, and the token and UserInfo
endpoints.

- **Crate:** `rs-identity-model` (not yet published to crates.io)
- **Edition:** 2024 · **MSRV:** 1.96
- **Build:** from source with `cargo build`

## Module Layout

| Module | Purpose | Spec |
|--------|---------|------|
| `discovery` | OIDC Discovery client | OIDC Discovery 1.0 |
| `jwks` | JWKS fetch + key resolution | RFC 7517 / 7518 |
| `jwt` | JWT signature + claims validation | RFC 7519 / 7515 |
| `token` | Client credentials, auth code, PKCE | RFC 6749 / 7636 |
| `userinfo` | UserInfo endpoint client | OIDC Core 1.0 §5.3 |
| `error` | `IdentityError` — the crate error type | — |

## Design Conventions

- Async via `tokio`; HTTP via `reqwest` with `rustls`.
- JWT handling via the `jsonwebtoken` crate.
- Builder-pattern configuration; `Result<T, IdentityError>` everywhere (`thiserror`).
- Caches use `tokio::sync::RwLock` for thread-safe async access.
- Security hardening: secrets are redacted from `Debug`/error output, `azp` and
  clock-skew are validated during JWT verification, and redirect-scheme downgrades
  are rejected.

## Getting Started

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test
cargo run --example basic_setup
```

Integration tests run against the shared provider in [`../infra`](../infra)
(`make infra-up` from the repo root).

## Capabilities

The Core tier (discovery, JWKS, JWT validation, client-credentials and
authorization-code + PKCE, UserInfo) is implemented. The Extended tier
(introspection, revocation, token exchange, DPoP) is in progress. Behavioral
parity with the Python and Go libraries is enforced by the cross-language
conformance vectors in [`../spec`](../spec).
