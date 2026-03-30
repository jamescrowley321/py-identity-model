task_id: T121
branch: test/integration-core-flows
worktree: /tmp/pim-T121
phase: ci-fix
pr: 279

## CI

### Failure: GitHub Actions never triggered

**Root cause:** PR #279 has merge state CONFLICTING. GitHub Actions CI (build.yml) never ran — only the Snyk external check passed.

**Conflicts (13 files):**
- .github/workflows/build.yml
- docs/api/index.md
- src/py_identity_model/__init__.py
- src/py_identity_model/aio/__init__.py
- src/py_identity_model/aio/token_validation.py
- src/py_identity_model/core/__init__.py
- src/py_identity_model/core/authorize_response.py (add/add)
- src/py_identity_model/core/models.py
- src/py_identity_model/sync/__init__.py
- src/py_identity_model/sync/token_validation.py
- src/tests/integration/test_authorize_callback.py (add/add)
- test-fixtures/node-oidc-provider/provider.js (add/add)

**Why:** T121 branch merged multiple feature branches (auth-code-pkce, enhanced-token-validation, refresh, introspection, revocation, http-client-di, oauth-callback-state). Since then, oauth-callback-state (#211) and node-oidc-fixture (#274) were merged to main, creating duplicate/conflicting changes.

**Fix plan (ci-fix phase):**
1. Merge origin/main into T121 worktree, resolving all 13 conflict files
2. For add/add conflicts: combine both sides
3. For content conflicts: accept main for already-merged features, keep branch additions
4. Run make lint and make test-unit to verify
5. Push to trigger CI
