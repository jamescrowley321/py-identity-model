# CHANGELOG

<!-- version list -->

## v2.0.0-rc.1 (2026-01-17)

### Bug Fixes

- Add retry logic to token client endpoint
  ([`8ec1cc6`](https://github.com/jamescrowley321/py-identity-model/commit/8ec1cc69e6bc4de45eec7d9276987a87be2c59b3))

- Add thread-safe SSL certificate backward compatibility for httpx
  ([`55b8fe4`](https://github.com/jamescrowley321/py-identity-model/commit/55b8fe4c4b717046c78052be95f0ba7d0a9f39d6))

- Address high priority issues from PR #108 code review
  ([`15ccf1d`](https://github.com/jamescrowley321/py-identity-model/commit/15ccf1d75f5ca58c5ef788b353e27c22349ff77c))

- Centralize HTTP default constants and improve content-type handling
  ([`0989b59`](https://github.com/jamescrowley321/py-identity-model/commit/0989b5985887cb8b3f816634aeb3cd105d1e5869))

- Export to_principal in root __init__.py
  ([`6443dec`](https://github.com/jamescrowley321/py-identity-model/commit/6443deca1fcb5dad4fc5e9e436c4deb7e079a310))

- Optimize token validation with multi-layer caching
  ([`e42dbb4`](https://github.com/jamescrowley321/py-identity-model/commit/e42dbb413bc20b81d3ade948798cc72ac614c6eb))

- Reduce code duplication and improve test coverage
  ([`3de5c0a`](https://github.com/jamescrowley321/py-identity-model/commit/3de5c0a9e755e02cac38613a20f92e6c9acea051))

- Remove private reset functions from public __all__ exports
  ([`a9bf2ef`](https://github.com/jamescrowley321/py-identity-model/commit/a9bf2efb6b1619373a773e40a7f14de81d175113))

- Sonar quality issues ([#126](https://github.com/jamescrowley321/py-identity-model/pull/126),
  [`34ab94b`](https://github.com/jamescrowley321/py-identity-model/commit/34ab94b880cbc6f3a6b581b5cc334ceedae8a7e0))

- Sonarcloud Quality Issues ([#115](https://github.com/jamescrowley321/py-identity-model/pull/115),
  [`7f74d78`](https://github.com/jamescrowley321/py-identity-model/commit/7f74d7811324bd1b7d4f765931df5193b1fc779c))

### Chores

- Remove implementation plan before PR merge
  ([`5ea55b4`](https://github.com/jamescrowley321/py-identity-model/commit/5ea55b4ec5965fd695f52f3f3b0a25007ae4352d))

### Continuous Integration

- Trigger prerelease on PR events with auto-versioning
  ([`bbd1fc7`](https://github.com/jamescrowley321/py-identity-model/commit/bbd1fc783b2ebc8cca7cc1d9b376c7de5354243c))

- Unify release workflow with workflow_dispatch for prereleases
  ([`735690c`](https://github.com/jamescrowley321/py-identity-model/commit/735690cf3e715edf391846df34957d06dd535913))

### Documentation

- Add httpx performance note to cached functions
  ([`05d969e`](https://github.com/jamescrowley321/py-identity-model/commit/05d969e593075b8da617505fc37fba393b35ed97))

- Add Phase 8 architecture improvements to roadmap
  ([`abe7397`](https://github.com/jamescrowley321/py-identity-model/commit/abe73975850376d2722772550c712c02b10abc9a))

- Complete Phase 5 documentation and examples
  ([`306e99f`](https://github.com/jamescrowley321/py-identity-model/commit/306e99f5db0275666f1e0d9df639b24a409a8063))

### Features

- Add async support and modular architecture
  ([`55af9f3`](https://github.com/jamescrowley321/py-identity-model/commit/55af9f37f32c7fccf639cdd463dbd79ad818360c))

- Add retry logic with exponential backoff for rate limiting
  ([`ef667e0`](https://github.com/jamescrowley321/py-identity-model/commit/ef667e071428bfc336b9e0fdcb8e9ae23566d38a))

- Add SSL certificate backward compatibility and fix Docker examples
  ([`808b16c`](https://github.com/jamescrowley321/py-identity-model/commit/808b16cc0f160b5d6f11e58f53bde02a146b0ddf))

- Complete async optimizations and add coverage reporting
  ([`155d682`](https://github.com/jamescrowley321/py-identity-model/commit/155d682adb861f9119a8581f34b6d133d32fa52d))

- Complete async support and add SonarCloud integration
  ([`70f5031`](https://github.com/jamescrowley321/py-identity-model/commit/70f5031f3a3879741ff4687b26ebc2c9293ff07c))

- Optimize integration tests with session-scoped fixtures
  ([`c01b691`](https://github.com/jamescrowley321/py-identity-model/commit/c01b69147ef326d343cf7ed2031be83925fafb53))

### Performance Improvements

- Add httpx connection pooling for sync HTTP requests
  ([`54952ee`](https://github.com/jamescrowley321/py-identity-model/commit/54952eef7cf55edf6870fa193b07721ffa8734ac))

- Add parallel test execution to all test commands
  ([`7496d72`](https://github.com/jamescrowley321/py-identity-model/commit/7496d7212348cc020a9c1b5cb7445b540c10f425))

- Add public key caching to async token validation
  ([`c34fbd3`](https://github.com/jamescrowley321/py-identity-model/commit/c34fbd3bcc3dfe6032ddb53a28856dced0d8cc46))

- Add selective parallel test execution to avoid rate limiting
  ([`7b88001`](https://github.com/jamescrowley321/py-identity-model/commit/7b8800110946b7c819cfad09c722b6e4cfe50b50))

### Refactoring

- Eliminate code duplication with shared response processors
  ([`5c023c6`](https://github.com/jamescrowley321/py-identity-model/commit/5c023c6a791b405976859ff5215a753df77de9b4))

- Extract common token validation logic to reduce duplication
  ([`b28779b`](https://github.com/jamescrowley321/py-identity-model/commit/b28779b062b711e03b169934d8e983a07c2c2781))

- Fix Sonar code quality issues
  ([`d52a03f`](https://github.com/jamescrowley321/py-identity-model/commit/d52a03f09d8b7dc787b2727bae30cd5f8b1d6ee0))

- Reduce code duplication by extracting shared logic
  ([`ea66a42`](https://github.com/jamescrowley321/py-identity-model/commit/ea66a42fc97d423054ec865ea89ed86068260364))

- Reduce cognitive complexity and eliminate string duplication
  ([`452ea1a`](https://github.com/jamescrowley321/py-identity-model/commit/452ea1ae9e0212012af24b885e0140ae68c36927))

### Testing

- Add cache validation tests and restore benchmark threshold
  ([`3c5de99`](https://github.com/jamescrowley321/py-identity-model/commit/3c5de99c987923c1a959bf50574c0a068acc2eb5))

- Add comprehensive coverage for parsers module
  ([`d1645f4`](https://github.com/jamescrowley321/py-identity-model/commit/d1645f417acbe08f86b9d2509de41b8e96ca87b4))

- Update network error test to handle both error types
  ([`41743e5`](https://github.com/jamescrowley321/py-identity-model/commit/41743e5b764ba347db3b32a05b77eeaa9023bcb3))


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
