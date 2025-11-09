# CHANGELOG

<!-- version list -->

## v1.2.0 (2025-11-08)

### Features

- **Async/Await Support** - Full asynchronous API via `py_identity_model.aio` module
  - Async versions of all client methods (discovery, JWKS, token validation, token client)
  - Async caching with `async-lru` for discovery and JWKS
  - Full backward compatibility maintained (sync API unchanged)
  - Comprehensive async test suite (10 new async tests)
  - Examples for both FastAPI and concurrent operations

- **Modular Architecture** - Clean separation between HTTP layer and business logic
  - Extracted shared business logic to `core/` module
  - Eliminated code duplication between sync/async implementations
  - Major code reduction: sync/jwks.py (390→78 lines), sync/discovery.py (378→246 lines)
  - All 146 tests passing with zero regressions

- **HTTP Client Migration** - Migrated from `requests` to `httpx`
  - Single library supporting both sync and async operations
  - Configurable timeouts (30s default on all HTTP calls)
  - Automatic connection pooling

- Add comprehensive logging and exception handling
  ([#107](https://github.com/jamescrowley321/py-identity-model/pull/107),
  [`98f88d6`](https://github.com/jamescrowley321/py-identity-model/commit/98f88d6c9def9f6bff9f7d8625acf258395a2275))

### Documentation

- Consolidate documentation into mkdocs instead of Wiki
  ([#99](https://github.com/jamescrowley321/py-identity-model/pull/99),
  [`71f5fcb`](https://github.com/jamescrowley321/py-identity-model/commit/71f5fcb9616c173be26864689bf4e3ba0351c52e))

- Add comprehensive async examples and architecture documentation
- Update roadmap to reflect completed features


## v1.1.1 (2025-10-21)

### Bug Fixes

- **docs**: Remove awesome-pages plugin to fix navigation
  ([`95904d7`](https://github.com/jamescrowley321/py-identity-model/commit/95904d750959ad8c4151134c8bef3103fc3b3fc3))

### Documentation

- Add CONTRIBUTING.md and fix documentation
  ([#98](https://github.com/jamescrowley321/py-identity-model/pull/98),
  [`68b266d`](https://github.com/jamescrowley321/py-identity-model/commit/68b266d4f93b8605a9acdc1a5b8958e6c66a52a3))


## v1.1.0 (2025-10-21)

### Chores

- Updates deps and docs ([#80](https://github.com/jamescrowley321/py-identity-model/pull/80),
  [`47c4ce2`](https://github.com/jamescrowley321/py-identity-model/commit/47c4ce2192316a6c1c7b3e2746c9ae22f1d69811))

### Features

- Put in some identity ([#82](https://github.com/jamescrowley321/py-identity-model/pull/82),
  [`a61cb9b`](https://github.com/jamescrowley321/py-identity-model/commit/a61cb9b8fbe95671ac9e84677051f3af42601fc7))


## v1.0.0 (2025-05-31)


## v1.0.0-rc.1 (2025-05-31)

### Chores

- Adds release automation
  ([`bd882e3`](https://github.com/jamescrowley321/py-identity-model/commit/bd882e3473fe4c8d41a01136a0467504da0f187c))

- Adds release automation
  ([`1d0ebad`](https://github.com/jamescrowley321/py-identity-model/commit/1d0ebadee9a7311577cbef9f8fd66553fa7adb4a))

- Adds release automation
  ([`d2f22cc`](https://github.com/jamescrowley321/py-identity-model/commit/d2f22cc42905bf0692889f79bad3f107283535ff))

- Fixes makefile
  ([`34096c3`](https://github.com/jamescrowley321/py-identity-model/commit/34096c36d558d12dd043e14a7fc7f5e7b4d226bc))

- Fixes makefile
  ([`b2ace65`](https://github.com/jamescrowley321/py-identity-model/commit/b2ace65b9c7f18be41f369a3b2675bbc095f85a4))

- Fixes workflow
  ([`cb2003b`](https://github.com/jamescrowley321/py-identity-model/commit/cb2003b720e1b9c59ae934a859c55eaaf5743904))

- Fixes workflow
  ([`ce5ed88`](https://github.com/jamescrowley321/py-identity-model/commit/ce5ed88d4cbd1550116acda3996922b393d80238))

- Fixes workflow
  ([`0e73021`](https://github.com/jamescrowley321/py-identity-model/commit/0e7302149d314216e532372231a35b3f8a9ab4dd))

- Updates cryptography to latest version
  ([#72](https://github.com/jamescrowley321/py-identity-model/pull/72),
  [`ea23f0d`](https://github.com/jamescrowley321/py-identity-model/commit/ea23f0d0d340d454a7f58490cd14a6b46a762a5c))

### Features

- Adds automated versioning
  ([`c4f9846`](https://github.com/jamescrowley321/py-identity-model/commit/c4f9846a51d3414ab57e1668decd6cf351f6e0b6))

- Adds automated versioning
  ([`05549ab`](https://github.com/jamescrowley321/py-identity-model/commit/05549abdbc1d8eeb82b41da0778db311782c75ac))

- Cleans up workflow files
  ([`425ed08`](https://github.com/jamescrowley321/py-identity-model/commit/425ed0840fd1224d87eb84ff708b23dea8499c47))

- Cleans up workflow files
  ([`b612011`](https://github.com/jamescrowley321/py-identity-model/commit/b61201148de7582d2f2c6b5ed24c067bb9998aed))

- Cleans up workflow files
  ([`f906d8c`](https://github.com/jamescrowley321/py-identity-model/commit/f906d8c5876408df9e3501d5cde5a891379fa72d))

- Cleans up workflow files
  ([`6febcbe`](https://github.com/jamescrowley321/py-identity-model/commit/6febcbe53ec61c2b0a7f00f9c3d9cce99ac61b68))

- Cleans up workflow files
  ([`38bff6f`](https://github.com/jamescrowley321/py-identity-model/commit/38bff6fef5ff58b149604f1e750b825fdff61890))

- Cleans up workflow files
  ([`30451ec`](https://github.com/jamescrowley321/py-identity-model/commit/30451ec38f691cedce7ad30ecff1aeda4011e3bf))

- Moves from poetry to uv
  ([`33cac19`](https://github.com/jamescrowley321/py-identity-model/commit/33cac199e25e635dd228cbcf9d34f935ce45582b))

- Moves from poetry to uv
  ([`1d5920e`](https://github.com/jamescrowley321/py-identity-model/commit/1d5920e14b1a4b5229c8f10909fc375e193510bb))


## v0.11.4 (2024-06-20)

- Initial Release
