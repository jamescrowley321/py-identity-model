# py-identity-model — polyglot OIDC/OAuth2.0 client libraries

A single repository housing production-grade OpenID Connect / OAuth 2.0 client
libraries in **Python, Go, and Rust**, validated against one shared,
language-neutral conformance specification and one shared set of local identity
providers.

| Path | What | Package |
|------|------|---------|
| [`py/`](py/) | Python core (JWT, discovery, JWKS, token validation) + `fastapi-identity-model` middleware. OIDF-certified; published to PyPI. | [`py-identity-model`](https://pypi.org/project/py-identity-model/) · [`fastapi-identity-model`](https://pypi.org/project/fastapi-identity-model/) |
| [`go/`](go/) | Go binding | `github.com/jamescrowley321/py-identity-model/go` |
| [`rust/`](rust/) | Rust binding | crate `rs-identity-model` |
| [`spec/`](spec/) | Language-neutral conformance vectors + capability matrix — the single source of truth every binding executes against. | — |
| [`infra/`](infra/) | Shared local IdP fixtures (node-oidc-provider, Duende IdentityServer, Keycloak) all suites test against; plus Descope Terraform. | — |
| [`conformance/`](conformance/) | The Python package's OIDF certification harness (black-box RP). Unchanged by the polyglot layout. | — |

> The Python package's own README (its PyPI long description) lives at
> [`py/README.md`](py/README.md).

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
