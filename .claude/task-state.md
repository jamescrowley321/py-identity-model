task_id: T122
branch: test/integration-token-mgmt
worktree: /tmp/pim-T122
phase: pr

## Plan

### Status: Implementation already complete

A previous iteration implemented and committed the integration tests (commits f9bc77a, 84798a5). The test file `src/tests/integration/test_node_oidc_token_mgmt.py` (367 lines) is complete.

### Test Phase Results

- **13/13 integration tests pass** against live node-oidc-provider (0.27s)
- **562/562 unit tests pass** with 94.32% coverage
- Fixture started, healthcheck verified, tests run, fixture torn down

## Review: Blind Hunter

### MUST FIX

- [conftest_node_oidc.py:335-349] **Session-scoped opaque token may expire mid-suite.** `node_oidc_cc_opaque_token` is session-scoped with ACCESS_TOKEN_TTL=300s. If the test session exceeds 5 minutes (e.g., slow CI, parallel with other integration suites), introspection of this cached token returns `active=False` and every test using it fails silently with wrong assertions. Fix: use `get_fresh_cc_opaque_token()` per-test or reduce to module scope with a fresh-token fallback.

- [test_node_oidc_token_mgmt.py] **No test for revocation with wrong client credentials.** There's `test_introspect_wrong_client_credentials` (line 99) but no equivalent error-path test for revocation. Per RFC 7009 §2.1, servers SHOULD verify client identity. Asymmetric error coverage — the library's revocation error handling path is untested against a real server.

- [test_node_oidc_token_mgmt.py:314,340] **Async tests close global singleton http client.** Both async tests call `close_async_http_client()` in the `finally` block. This closes the process-wide singleton. If pytest test ordering places any other async test after these, the singleton is dead. This creates a hidden test-ordering dependency and intermittent failures.

- [conftest_node_oidc.py:421-440 vs 335-349] **Inconsistent token acquisition: library vs raw httpx.** Session fixture `node_oidc_cc_opaque_token` uses the library (`request_client_credentials_token`), but per-test helper `get_fresh_cc_opaque_token` uses raw `httpx.post`. If the library has a bug in client_credentials token requests, per-test helper still works and test passes — masking the bug. Pick one approach.

### SHOULD FIX

- [test_node_oidc_token_mgmt.py:340] **Async test mixes sync and async I/O.** `test_async_revoke_and_verify` calls sync `get_fresh_cc_opaque_token()` which blocks the event loop with `httpx.post`. Violates the library's dual API design philosophy ("Don't mix sync and async"). Should use an async equivalent.

- [test_node_oidc_token_mgmt.py:99-110] **`test_introspect_wrong_client_credentials` doesn't assert HTTP status or error code.** Only checks `is_successful is False` and `error is not None`. A 500 Internal Server Error would also pass. Should assert specific error pattern (401 or `invalid_client`).

- [conftest_node_oidc.py:381-396] **`node_oidc_revocation_endpoint` duplicates discovery fetch.** The fixture makes a separate raw HTTP GET to the discovery URL because `DiscoveryDocumentResponse` lacks `revocation_endpoint`. This is a library model gap (RFC 7009 §2 says servers SHOULD include it in metadata per RFC 8414). The workaround works but hides the gap.

- [models.py:DiscoveryDocumentResponse] **`revocation_endpoint` missing from discovery model.** RFC 8414 defines `revocation_endpoint` as a standard authorization server metadata field. The model has `introspection_endpoint` but not `revocation_endpoint`. This forces the test into a raw-HTTP workaround and means production code can't discover the revocation endpoint via the library.

- [test_node_oidc_token_mgmt.py:112-136] **`test_introspect_custom_claims` only verifies one tenant.** The provider emits two tenants (`test-tenant-1` with admin role, `test-tenant-2` with viewer role). The test only checks `test-tenant-1`. Incomplete claim verification — a provider bug dropping `test-tenant-2` would go undetected.

- [test_node_oidc_token_mgmt.py] **No test for `token_type_hint="refresh_token"` in introspection.** Tests cover `access_token` hint and no hint, but RFC 7662 §2.1 allows `refresh_token` as a hint. Missing coverage.

### NITPICK

- [test_node_oidc_token_mgmt.py] **Repeated `TokenIntrospectionRequest` construction.** Every introspection test builds the same request with minor variations. A helper `_make_introspect_request(token, **overrides)` would reduce copy-paste and make tests more readable.

- [test_node_oidc_token_mgmt.py] **"CC" abbreviation used in docstrings without definition.** "CC token" (Client Credentials) appears in multiple docstrings but is never expanded.

- [test_node_oidc_token_mgmt.py:147-160] **`test_revoke_access_token` doesn't verify revocation took effect.** It only checks `is_successful=True` — but revocation succeeds even for invalid tokens. Without a follow-up introspection, you can't distinguish "revoked" from "no-op success". (Covered by `test_revoke_then_introspect_inactive` but this test alone proves nothing.)

- [test_node_oidc_token_mgmt.py:192-221] **`test_revoke_with_type_hint` and `test_revoke_invalid_token` don't add value beyond `test_revoke_access_token`.** Per RFC 7009, type_hint is just an optimization hint and invalid tokens succeed anyway. These tests confirm the spec but don't exercise different code paths.

- [conftest_node_oidc.py:421-440] **`get_fresh_cc_opaque_token` uses `pytest.fail` outside test context.** While this works when called from tests, `pytest.fail` raises `Failed` exception which would have confusing tracebacks if the function were ever used in a non-pytest context (e.g., debugging scripts).

## Review: Edge Case Hunter

```json
[
  {
    "location": "conftest_node_oidc.py:387-393",
    "trigger_condition": "Provider returns HTTP 200 with non-JSON body for discovery",
    "guard_snippet": "try: data = resp.json() except ValueError: pytest.fail('Discovery returned non-JSON for revocation endpoint')",
    "potential_consequence": "Raw ValueError traceback instead of clear test failure message"
  },
  {
    "location": "conftest_node_oidc.py:429-438",
    "trigger_condition": "get_fresh_cc_opaque_token gets HTTP 200 with non-JSON body",
    "guard_snippet": "try: return resp.json() except ValueError: pytest.fail('Token response is not JSON')",
    "potential_consequence": "Raw ValueError traceback hides which fixture failed"
  },
  {
    "location": "test_node_oidc_token_mgmt.py:135-136",
    "trigger_condition": "Provider custom claims structure changes or roles key absent",
    "guard_snippet": "assert 'roles' in tenants['test-tenant-1'], 'Missing roles key in tenant claims'",
    "potential_consequence": "Raw KeyError instead of assertion explaining claim mismatch"
  },
  {
    "location": "test_node_oidc_token_mgmt.py:329-330",
    "trigger_condition": "Test assertion fails AND close_async_http_client() also raises",
    "guard_snippet": "Use contextlib.suppress or separate try/except in finally for close_async_http_client()",
    "potential_consequence": "Original AssertionError swallowed by finally-block exception"
  },
  {
    "location": "test_node_oidc_token_mgmt.py:340",
    "trigger_condition": "Async test calls sync httpx.post via get_fresh_cc_opaque_token",
    "guard_snippet": "Create async_get_fresh_cc_opaque_token using httpx.AsyncClient",
    "potential_consequence": "Event loop blocked during sync I/O, stalls concurrent coroutines"
  },
  {
    "location": "revocation_logic.py:37 vs introspection_logic.py:40",
    "trigger_condition": "client_secret is empty string (not None)",
    "guard_snippet": "Align both: use 'if request.client_secret is not None:' consistently",
    "potential_consequence": "Introspection sends auth=('id',''), revocation sends client_id as param"
  },
  {
    "location": "sync/introspection.py:57-58",
    "trigger_condition": "response.close() raises after result is computed",
    "guard_snippet": "Move response.close() to finally block (like sync/revocation.py does)",
    "potential_consequence": "Valid introspection result discarded, error response returned instead"
  },
  {
    "location": "conftest_node_oidc.py:335-349",
    "trigger_condition": "Session-scoped opaque token response has no access_token key",
    "guard_snippet": "assert 'access_token' in response.token, 'CC token response missing access_token'",
    "potential_consequence": "KeyError in every test using fixture with no context on root cause"
  }
]
```

## Review: Acceptance Auditor

### PASS

- **[RFC 7662] Introspect active token** — implemented at `test_node_oidc_token_mgmt.py:49`, asserts `active=True`, `client_id`, `iss`, `exp`, `iat`
- **[RFC 7662] Introspect with token_type_hint** — implemented at `test_node_oidc_token_mgmt.py:66`, passes `token_type_hint="access_token"`
- **[RFC 7662] Introspect invalid token → active=False** — implemented at `test_node_oidc_token_mgmt.py:80`, per §2.2
- **[RFC 7662] Introspect with wrong client credentials → error** — implemented at `test_node_oidc_token_mgmt.py:92`
- **[RFC 7662] Custom claims (dct/tenants) in introspection** — implemented at `test_node_oidc_token_mgmt.py:112`, verifies Descope-style claims
- **[RFC 7009] Revoke valid token** — implemented at `test_node_oidc_token_mgmt.py:147`
- **[RFC 7009] Revoke with token_type_hint** — implemented at `test_node_oidc_token_mgmt.py:192`
- **[RFC 7009] Revoke invalid token → still succeeds (§2.2)** — implemented at `test_node_oidc_token_mgmt.py:204`
- **[RFC 7009] Revoke idempotency** — implemented at `test_node_oidc_token_mgmt.py:212`, calls revoke twice
- **[Lifecycle] Issue → introspect (active) → revoke → introspect (inactive)** — implemented at `test_node_oidc_token_mgmt.py:239`, full round-trip
- **[Async] Async introspection** — implemented at `test_node_oidc_token_mgmt.py:304`
- **[Async] Async revocation + verify** — implemented at `test_node_oidc_token_mgmt.py:325`
- **[Infra] Tests run against live node-oidc-provider** — all tests use real HTTP, no mocks
- **[Infra] Opaque tokens used for introspection/revocation** — documented reason in module docstring (node-oidc can't introspect JWTs)
- **[Infra] Tests marked with `@pytest.mark.node_oidc`** — proper marker isolation

### FAIL

- **[RFC 7009] No error-path test for revocation with wrong client credentials.** Introspection has `test_introspect_wrong_client_credentials` but revocation has no equivalent. Per RFC 7009 §2.1, the authorization server SHOULD verify client identity for revocation requests. The library's revocation error handling path is untested against a real provider.

### PARTIAL

- **[RFC 7662] Error assertion specificity.** `test_introspect_wrong_client_credentials` only checks `is_successful is False` and `error is not None` — doesn't assert the error code (`invalid_client`) or HTTP status, so a 500 would also pass.
- **[RFC 7662] Custom claims verification incomplete.** `test_introspect_custom_claims` checks only `test-tenant-1`. The provider emits two tenants (`test-tenant-1` admin, `test-tenant-2` viewer); a provider bug dropping `test-tenant-2` goes undetected.
- **[RFC 8414] `revocation_endpoint` missing from `DiscoveryDocumentResponse`.** The model has `introspection_endpoint` but not `revocation_endpoint` (defined in RFC 8414 §2). This forces the conftest into a raw HTTP workaround and means production callers can't discover the revocation endpoint through the library.
- **[Async] Singleton lifecycle hazard.** Both async tests close the global `async_http_client` singleton in `finally`. This kills the client for any subsequent async tests in the process. Should use `contextlib.suppress` or per-test client scope.

## Review: Security (Sentinel)

### BLOCK

None.

### WARN

- [sync/introspection.py:57-58] **response.close() not in finally block.** If `process_introspection_response` raises, `response.close()` is never called — leaking the HTTP connection back to the pool in an unread state. The sync revocation module correctly uses `finally` for cleanup. Inconsistency between the two modules.

- [core/introspection_logic.py:40 vs core/revocation_logic.py:37] **Client secret emptiness check inconsistency.** Introspection uses `if request.client_secret is not None:` — an empty string `""` would be sent as HTTP Basic auth with empty password. Revocation uses `if request.client_secret and request.client_secret.strip():` — an empty string falls through to putting `client_id` in the POST body. Different auth behavior for the same edge case across the two modules.

- [test-fixtures/node-oidc-provider/package.json] **Caret version ranges for dependencies.** `jose: ^6.0.11` and `oidc-provider: ^9.7.1` allow minor/patch bumps. While `npm ci` with the lockfile mitigates this for reproducible builds, `npm install` (first lock generation or lock refresh) pulls latest in range. Pin exact versions for CI reproducibility.

- [core/response_processors.py] **Error messages include raw response content.** `parse_introspection_response`, `parse_token_response`, and `parse_auth_code_token_response` embed `response.content` (bytes) in error messages. If the auth server returns a stack trace or internal details on error, these propagate to callers via the `error` field. Not exploitable, but information exposure if error messages are logged at higher verbosity.

### INFO

- [Dockerfile:11] **Container runs as non-root** — `USER node` correctly drops privileges. Good.
- [docker-compose.yml] **Port bound to localhost only** — `127.0.0.1:9010:9010` prevents external access. Good.
- [conftest_node_oidc.py] **Test credentials clearly test-scoped** — All client IDs/secrets prefixed with `test-` (e.g., `test-client-credentials`, `test-auth-code-secret`). No risk of confusion with real credentials.
- [provider.js:263] **HTTP-only fixture with `provider.proxy = true`** — Acceptable for local testing per project conventions. Would be a vulnerability in any non-local context.
- [provider.js:140-157] **Raw HTML interpolation in `userCodeInputSource`** — Template literal embeds `form` and `err.message` without escaping. Documented with comment as intentional for test fixture. Not exploitable since only localhost-bound, but a footgun if fixture scope changes.
