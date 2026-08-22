# identity-model

**One OIDC/OAuth2 client library, in every language, that behaves the same everywhere.**

Outside of .NET, writing an OpenID Connect or OAuth 2.0 *client* means gluing
together three or four half-overlapping libraries per language — one for JWTs,
another for discovery, a third for the flows — each with its own quirks, its own
gaps, and no relationship to what you'd reach for in the next service written in
a different language. Duende's IdentityModel solved this for C#: one coherent,
RFC-compliant client library with clean abstractions. Nothing equivalent exists
for the rest of the stack.

**identity-model** is that library, brought to Python, Go, and Rust (Node/TypeScript
next). Not four unrelated ports — one design, one capability surface, one set of
RFC-compliance guarantees, implemented natively and idiomatically in each language
and held to a single shared behavioral contract. Move from a Python service to a
Go one and the mental model comes with you.

- **RFC-first** — every capability maps to a specific RFC or OpenID Connect section, not a vendor's happy path.
- **Native, not bindings** — each library is real, idiomatic code in its own language (`httpx`/`net/http`/`reqwest`), sharing a design, not a runtime.
- **Provably consistent** — one language-neutral [conformance spec](spec/) defines the expected behavior as executable vectors, and every language must pass every vector (enforced in CI).
- **Provider-agnostic** — Descope, Okta, Auth0, Keycloak, Entra, or any spec-compliant provider.

It is a protocol **client** library: it talks to identity providers. It is **not**
an identity provider or authorization server (no token issuance, no consent
screens), and not framework middleware — though middleware is built on top of it
(see [`fastapi-identity-model`](py/packages/fastapi-identity-model)).

Credit where due: the design philosophy, capability taxonomy, and
spec-compliance bar are a deliberate port of
[Duende IdentityModel](https://github.com/DuendeSoftware/foss/tree/main/identity-model).

## The libraries

| Language | Status | Install |
|----------|--------|---------|
| **Python** — [`py/`](py/) | Production-proven and **OpenID Foundation certified**. The reference implementation the others are measured against. Full Core + Extended surface. | `pip install py-identity-model` |
| **Go** — [`go/`](go/) | Core + Extended (introspection, revocation, token exchange, DPoP) implemented. | `go get github.com/jamescrowley321/py-identity-model/go` |
| **Rust** — [`rust/`](rust/) | Core implemented; Extended in progress. Not yet published to crates.io. | build from source (crate `rs-identity-model`) |
| **Node / TypeScript** | Planned. | — |

Capabilities span discovery, JWKS retrieval with caching, JWT validation, the
client-credentials / authorization-code+PKCE / refresh / device flows, UserInfo,
token introspection and revocation, token exchange, and DPoP — see the
per-language READMEs and the [capability matrix](spec/capabilities.md) for the
authoritative, RFC-referenced status of each in each language.

## What makes the guarantee real

The claim "every library behaves the same" is only worth anything if it's
enforced. It is:

- **[`spec/`](spec/)** — a language-neutral capability spec plus machine-readable
  conformance vectors: inputs and expected outcomes expressed as canonical,
  cross-language error codes. This is the single source of truth for *what
  correct means*.
- Each language runs those vectors through a thin executor, and a **cross-language
  coverage gate** fails CI if any language skips any vector (`make spec-coverage`).
- **[`conformance/`](conformance/)** — the Python library additionally passes the
  OpenID Foundation's official certification suite.
- **[`infra/`](infra/)** — one shared set of local identity providers
  (node-oidc-provider, Keycloak, Duende IdentityServer) that every language's
  integration tests run against, so "works against a real provider" means the
  same thing for all of them.

## Repository layout

A polyglot monorepo — each language keeps its own native toolchain.

```
py/    Python library + fastapi-identity-model middleware   (uv, PyPI)
go/    Go library                                            (go)
rust/  Rust library — crate rs-identity-model                (cargo)
spec/  cross-language conformance spec + vectors
infra/ shared local identity-provider fixtures
```

```bash
cd py && uv sync --all-packages && uv run pytest src/tests -m unit   # Python
cd go && go test ./...                                               # Go
cd rust && cargo test                                                # Rust
```

The repo-root `Makefile` wraps the common flows: `make infra-up` brings the
shared providers up, `make test-integration-{node-oidc,keycloak,go,rust}` run the
integration suites, and `make spec-coverage` runs the cross-language conformance
gate. See [`spec/README.md`](spec/README.md) and [`infra/README.md`](infra/README.md).

## License

Apache-2.0. See [`LICENSE`](LICENSE).
