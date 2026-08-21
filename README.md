# py-identity-model — polyglot OIDC/OAuth2.0 client libraries

A single repository housing production-grade OpenID Connect / OAuth 2.0 client
libraries in **Python, Go, and Rust**, validated against one shared,
language-neutral conformance specification and one shared set of local identity
providers.

Each library is a standalone, idiomatic implementation in its own language —
not a wrapper over a shared core — and every one is held to the same behavior
by the conformance vectors in [`spec/`](spec/).

| Path | Library | Install |
|------|---------|---------|
| [`py/`](py/) | Python — the OIDF-certified reference. Ships the core library plus the `fastapi-identity-model` middleware. | [`py-identity-model`](https://pypi.org/project/py-identity-model/) · [`fastapi-identity-model`](https://pypi.org/project/fastapi-identity-model/) (PyPI) |
| [`go/`](go/) | Go | `go get github.com/jamescrowley321/py-identity-model/go` |
| [`rust/`](rust/) | Rust | crate `rs-identity-model` (build from source) |

Supporting directories:

| Path | Purpose |
|------|---------|
| [`spec/`](spec/) | The language-neutral capability spec and conformance vectors every library is tested against. |
| [`infra/`](infra/) | Shared local identity-provider fixtures (node-oidc-provider, Duende IdentityServer, Keycloak) the integration suites run against. |
| [`conformance/`](conformance/) | The Python library's OpenID Foundation certification harness. |

The Python library's own README (its PyPI description) is at
[`py/README.md`](py/README.md).

## Working in this repo

Each language keeps its native toolchain:

```bash
# Python (from py/)
cd py && uv sync --all-packages && uv run pytest src/tests -m unit

# Go
cd go && go test ./...

# Rust
cd rust && cargo test
```

The repo-root [`Makefile`](Makefile) wraps the common flows —
`make infra-up` / `make infra-down` bring the shared IdP fixtures up,
`make test-integration-{node-oidc,keycloak,go,rust}` run the per-language
integration suites against them, and `make spec-coverage` runs the
cross-language `/spec` vector-coverage gate (every language must execute every
vector). See [`spec/README.md`](spec/README.md) and [`infra/README.md`](infra/README.md).

## License

Apache-2.0. See [`LICENSE`](LICENSE).
