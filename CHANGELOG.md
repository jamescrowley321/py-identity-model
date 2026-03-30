# CHANGELOG

<!-- version list -->

## v2.12.0 (2026-03-30)


## v2.11.0 (2026-03-30)

### Features

- **par**: Implement Pushed Authorization Requests (RFC 9126)
  ([#230](https://github.com/jamescrowley321/py-identity-model/pull/230),
  [`aa655ba`](https://github.com/jamescrowley321/py-identity-model/commit/aa655bae0d1f5230895dcb453903e923bcf1ab79))


## v2.10.0 (2026-03-30)

### Features

- **dpop**: Implement DPoP proof creation and key management (RFC 9449)
  ([#229](https://github.com/jamescrowley321/py-identity-model/pull/229),
  [`994012e`](https://github.com/jamescrowley321/py-identity-model/commit/994012ed746bd5e6ee6ef4f59f298ee34f7bb830))


## v2.9.0 (2026-03-30)

### Features

- **refresh**: Implement OAuth 2.0 Refresh Token Grant
  ([#228](https://github.com/jamescrowley321/py-identity-model/pull/228),
  [`c0eae00`](https://github.com/jamescrowley321/py-identity-model/commit/c0eae004b9b33e2e2d4ad658d772cdcae4e3fccc))


## v2.8.0 (2026-03-30)


## v2.7.0 (2026-03-30)

### Features

- **introspection**: Implement OAuth 2.0 Token Introspection (RFC 7662)
  ([#226](https://github.com/jamescrowley321/py-identity-model/pull/226),
  [`6870781`](https://github.com/jamescrowley321/py-identity-model/commit/6870781318a6163e1e2f8dc1add185ec7eee85d2))


## v2.6.0 (2026-03-30)

### Features

- **auth-code**: Implement Authorization Code Grant with PKCE
  ([#225](https://github.com/jamescrowley321/py-identity-model/pull/225),
  [`f3ea096`](https://github.com/jamescrowley321/py-identity-model/commit/f3ea0966930a5408e4d6c581790637f4c49b041d))


## v2.5.0 (2026-03-30)

### Features

- **token-validation**: Add enhanced validation and base request/response classes
  ([#224](https://github.com/jamescrowley321/py-identity-model/pull/224),
  [`c137b27`](https://github.com/jamescrowley321/py-identity-model/commit/c137b272852cf8c6c449c9acef0477f44cca74ac))


## v2.4.1 (2026-03-30)

### Bug Fixes

- **ci**: Remove tracked worktree directory breaking CI checkout
  ([`4fbaa7e`](https://github.com/jamescrowley321/py-identity-model/commit/4fbaa7e68572a9c8feb56cee0518cc58f1cf42c0))


## v2.4.0 (2026-03-30)

### Features

- **http-client**: Add dependency injection support for HTTP client management
  ([#222](https://github.com/jamescrowley321/py-identity-model/pull/222),
  [`4ad60f2`](https://github.com/jamescrowley321/py-identity-model/commit/4ad60f2cffbddc149ed307b93fbb427235008dff))


## v2.3.0 (2026-03-30)

### Bug Fixes

- **authorize**: Address code review and security findings
  ([`1976416`](https://github.com/jamescrowley321/py-identity-model/commit/197641689b20b4b6236cc6c9a66c958397598035))

- **authorize**: Guard against None inputs in callback parsing and state validation
  ([`2e696c5`](https://github.com/jamescrowley321/py-identity-model/commit/2e696c50d733aef2bfd528470b4c7c61ef8039bc))

- **authorize**: Make state accessible on error responses per RFC 6749
  ([`1a77957`](https://github.com/jamescrowley321/py-identity-model/commit/1a77957654c8f6241a115e000b13ee500bbc8eba))

- **test**: Make authorization_endpoint HTTPS assertion conditional on require_https
  ([`2cd2801`](https://github.com/jamescrowley321/py-identity-model/commit/2cd2801c55021e3ad47248d3dddf2c1950f11c79))

### Chores

- Auto-commit before merge (loop primary)
  ([`7e42771`](https://github.com/jamescrowley321/py-identity-model/commit/7e42771145d9a7781e5a42fce16bcf69781e23b3))

- Exclude __init__.py from SonarCloud duplication analysis
  ([`7886657`](https://github.com/jamescrowley321/py-identity-model/commit/78866576731b343f917e08aa8d4c375d175224c9))

- **deps**: Automated dependency update
  ([`244735d`](https://github.com/jamescrowley321/py-identity-model/commit/244735da8b1e988e1cef909ba82c892f61e8831e))

- **deps**: Automated dependency update
  ([`b0ed1fe`](https://github.com/jamescrowley321/py-identity-model/commit/b0ed1fef76bb3af607dd8fadb393485f68bcd63f))

- **deps**: Automated dependency update
  ([`104cb62`](https://github.com/jamescrowley321/py-identity-model/commit/104cb62ffcc74e27c05553a80809e525d0d67584))

### Continuous Integration

- Add pull_request trigger to build workflow
  ([`30399f9`](https://github.com/jamescrowley321/py-identity-model/commit/30399f9225db4d4fb5e68404359c823aaebf0a62))

### Documentation

- **authorize**: Add API docs for callback response and state validation
  ([`41b63b6`](https://github.com/jamescrowley321/py-identity-model/commit/41b63b6463880cdc61e5bb9f552234bf46582ec5))

- **authorize**: Add authorization callback usage examples
  ([`530cec6`](https://github.com/jamescrowley321/py-identity-model/commit/530cec6c65ab305d83cae416446ba7b18c9e2bf0))

### Features

- **authorize**: Add AuthorizeCallbackResponse model and parser
  ([`4d8351f`](https://github.com/jamescrowley321/py-identity-model/commit/4d8351f1024a534ad95963a4e5bbac180312baea))

- **authorize**: Add state parameter validation
  ([`2f4f826`](https://github.com/jamescrowley321/py-identity-model/commit/2f4f826c5144990ae6c528fef77ab2ff21025d5e))

- **authorize**: Export callback response and state validation API
  ([`6c3ddd9`](https://github.com/jamescrowley321/py-identity-model/commit/6c3ddd93fcf359eb3b339c67de440e7eb7f94f7f))

- **exceptions**: Add AuthorizeCallbackException
  ([`4804ae2`](https://github.com/jamescrowley321/py-identity-model/commit/4804ae25c728238f259968b07ac318296faa4f58))

### Refactoring

- **test**: Reduce code duplication in authorize callback tests
  ([`76dfc6c`](https://github.com/jamescrowley321/py-identity-model/commit/76dfc6c69f35026cd9caa06346fdfa71ad77a819))

### Testing

- Add coverage for review fix findings
  ([`e4a396a`](https://github.com/jamescrowley321/py-identity-model/commit/e4a396a2bf6193ba340a614a4229aff2e294da3e))

- **authorize**: Add integration tests for callback parsing and state validation
  ([`02a9f94`](https://github.com/jamescrowley321/py-identity-model/commit/02a9f94b9491bc35780ab46ffcf080c8e18c8c65))

- **authorize**: Add unit tests for callback response and state validation
  ([`1b83e10`](https://github.com/jamescrowley321/py-identity-model/commit/1b83e10f7e5c2247d34da4c2772a6ebd51484598))


## v2.2.0 (2026-03-14)

### Features

- Add guarded field access on failed response models
  ([#200](https://github.com/jamescrowley321/py-identity-model/pull/200),
  [`1e2b7ba`](https://github.com/jamescrowley321/py-identity-model/commit/1e2b7ba3622492ffa0715437decc030e632f3ad8))


## v2.1.5 (2026-03-10)

### Bug Fixes

- Add Terraform and TFLint setup to release workflow
  ([#189](https://github.com/jamescrowley321/py-identity-model/pull/189),
  [`d76de12`](https://github.com/jamescrowley321/py-identity-model/commit/d76de12a5cd07473c32394d478f0263be7b660f6))


## v2.1.4 (2026-02-24)

### Bug Fixes

- **hooks**: Remove unnecessary bash -c wrappers from pre-commit config
  ([#183](https://github.com/jamescrowley321/py-identity-model/pull/183),
  [`e2bab26`](https://github.com/jamescrowley321/py-identity-model/commit/e2bab26b44a654ea2c77e1d737c4c3a2d8e7686b))


## v2.1.3 (2026-02-24)

### Bug Fixes

- **test**: Warm lru_cache before benchmark to avoid 429 rate limits
  ([#182](https://github.com/jamescrowley321/py-identity-model/pull/182),
  [`ee6fa2f`](https://github.com/jamescrowley321/py-identity-model/commit/ee6fa2faadd601b019d70dba0343072c80e982dd))


## v2.1.2 (2026-02-24)

### Bug Fixes

- **docs**: Switch GitHub Pages to Actions deployment and add docs targets
  ([#181](https://github.com/jamescrowley321/py-identity-model/pull/181),
  [`7ba1135`](https://github.com/jamescrowley321/py-identity-model/commit/7ba11351bdb926829dad1655e7839bcecff2070a))


## v2.1.1 (2026-02-24)

### Bug Fixes

- **docs**: Resolve MkDocs strict mode build failures
  ([#179](https://github.com/jamescrowley321/py-identity-model/pull/179),
  [`bec22b4`](https://github.com/jamescrowley321/py-identity-model/commit/bec22b4dba82b8725578494461b40bc2482c23c5))


## v2.1.0 (2026-02-18)

### Build System

- Consolidate dependabot dependency updates
  ([#175](https://github.com/jamescrowley321/py-identity-model/pull/175),
  [`e9ae811`](https://github.com/jamescrowley321/py-identity-model/commit/e9ae81150ee005c68d6de5291b3a02f5a7b7baaa))

### Features

- **userinfo**: Add OpenID Connect UserInfo endpoint support
  ([`9e35dce`](https://github.com/jamescrowley321/py-identity-model/commit/9e35dce4ead829c2b0676d4c9180714685f24cd2))


## v2.0.0 (2026-01-29)


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
