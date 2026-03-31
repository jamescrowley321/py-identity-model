You are in a self-referential implementation loop. Each iteration you execute ONE phase of ONE task, then end your response. The loop gives you a fresh context each iteration — persist all state to files.

## Directive

**Quality gates only. No new features.** This loop fixes test quality, removes dead code, strengthens assertions, and adds missing coverage. Every PR must leave the codebase in a strictly better state with no regressions.

## Task Queue

Tasks are chained — each branches from the previous task's branch to avoid merge conflicts. Execute sequentially.

| Task | Issue | Branch | Base Branch | Description | Status |
|------|-------|--------|-------------|-------------|--------|
| Q1 | 289 | chore/remove-dead-code | chore/code-quality-audit | Remove `_current_env_file` dead global in test_utils.py and empty `setup_test_environment` fixture in conftest.py | done |
| Q2 | 285 | chore/delete-import-smoke-tests | chore/remove-dead-code | Delete 10 redundant `test_top_level_import`/`test_aio_import` tests across 5 integration files (test_device_auth, test_discovery_policy, test_fapi, test_jar, test_token_exchange) | pending |
| Q3 | 288 | chore/fix-mutable-test-state | chore/delete-import-smoke-tests | Extract `DEFAULT_OPTIONS` dict from 3 test files into shared frozen fixture in conftest.py. Fix `cache_info[0]` → `.hits` in test_token_validation.py | pending |
| Q4 | 287 | chore/consolidate-test-duplicates | chore/fix-mutable-test-state | Absorb test_jwks.py into test_json_web_key.py. Consolidate expired-token and benchmark duplicates from test_token_validation.py into test_token_validation_cache.py | pending |
| Q5 | 284 | refactor/reclassify-integration-tests | chore/consolidate-test-duplicates | Move ~30 pure-constructor/model tests from `src/tests/integration/` to `src/tests/unit/`. Files: test_base_classes.py (full), test_par.py (full), test_revocation.py (full), plus constructor-only tests from test_device_auth, test_discovery_policy, test_fapi, test_introspection, test_token_exchange | pending |
| Q6 | 286 | fix/noop-validator-tests | refactor/reclassify-integration-tests | Fix 3 no-op claims validator tests to prove invocation via side-effect tracking. Files: test_aio_token_validation.py, test_token_validation.py | pending |
| Q7 | 290 | fix/retry-cascade | fix/noop-validator-tests | Remove redundant tenacity retry layer in integration conftest.py. The library already retries 429s internally — the conftest retry creates a 3×3 cascade (up to 9 requests). Trust library retry or replace with simple retry on is_successful=False | pending |
| Q8 | 291 | chore/config-validation | fix/retry-cascade | Add validation in test_utils.get_config() for required non-empty config values. Create .env.example with placeholder values documenting required variables | pending |
| Q9 | 292 | chore/strengthen-assertions | chore/config-validation | Strengthen ~15 truthy-only assertions to check specific expected values. Replace `assert decoded["iss"]` with `assert decoded["iss"] == issuer`, fix DPoP JKT length to exact 43 chars, etc. | pending |
| Q10 | 293 | test/async-integration | chore/strengthen-assertions | Add async integration tests for aio.get_discovery_document and aio.get_jwks. Extract inline try/finally cleanup pattern in test_aio_token_validation.py to conftest fixture | pending |

## Step 1: Determine Context

1. Read `~/repos/auth/CLAUDE.md` for repo commands and git conventions
2. The target repo is `py-identity-model` at `~/repos/auth/py-identity-model`
3. Read `~/repos/auth/py-identity-model/CLAUDE.md` for py-identity-model-specific commands and patterns
4. Read the audit report at `~/repos/auth/auth-planning/_bmad-output/implementation-artifacts/pim-code-quality-audit-report.md` for full context on findings

## Step 2: Determine What To Do

Read `~/repos/auth/py-identity-model/.claude/task-state.md`.

- **Does not exist** → Pick up next task (Step 3)
- **phase is `complete`** → Update queue status in THIS prompt file (replace `pending` with `done` for that row), delete task-state.md, pick up next task (Step 3)
- **Any other phase** → Execute that one phase (Step 4)

## Step 3: Pick Up Next Task

Find the first `pending` row in the Task Queue above.

- If none eligible (all done) → output: <promise>LOOP_COMPLETE</promise>
- Otherwise:
  1. Create `~/repos/auth/py-identity-model/.claude/task-state.md`:
     ```
     task_id: QX
     issue: <number>
     repo: py-identity-model
     branch: <branch from queue>
     base_branch: <base branch from queue>
     description: <desc>
     phase: setup
     ```
  2. Execute the `setup` phase below, then end your response

## Step 4: Execute ONE Phase

Read phase from task-state.md. Execute ONLY that phase. When done, update the phase field to the next phase and end your response.

**All work happens in the repo directory** — `cd ~/repos/auth/py-identity-model` before doing anything.

Phase order:

```
setup → analyze → implement → test → review-blind → review-edge → review-fix → pr → ci → ci-fix (loop) → complete
```

---

### setup

1. `cd ~/repos/auth/py-identity-model`
2. Fetch latest: `git fetch origin`
3. Create branch from base: `git checkout -b <branch> origin/<base_branch>` (if base_branch doesn't exist on remote yet, use the local branch)
   - For Q1: base is `chore/code-quality-audit` (already exists locally)
   - For Q2+: base is the previous task's branch (should exist locally from prior task)
4. Verify: `git log --oneline -5`
5. **Set phase to `analyze`. End your response.**

---

### analyze

`cd ~/repos/auth/py-identity-model`

1. Read the GitHub issue for this task: `gh issue view <issue_number> --repo jamescrowley321/py-identity-model`
2. Read the relevant source files identified in the issue
3. Read the audit report section relevant to this task
4. Write analysis notes to `## Analysis` section in task-state.md:
   - Files to modify
   - Specific changes needed
   - Risk assessment
   - What to verify after changes
5. **Set phase to `implement`. End your response.**

---

### implement

**Persona:** Read `~/repos/auth/auth-planning/_bmad/bmm/agents/dev.md` — adopt Amelia's mindset.

1. Read `## Analysis` from task-state.md
2. Make the changes identified in analysis
3. After each logical change:
   - Run `uv run ruff check src/` and `uv run ruff format src/`
   - Fix any lint issues immediately
4. Commit with conventional commit messages referencing the issue:
   ```
   chore: <description> (#<issue>)
   ```
   or
   ```
   fix: <description> (#<issue>)
   ```
   or
   ```
   refactor: <description> (#<issue>)
   ```
   or
   ```
   test: <description> (#<issue>)
   ```
5. **CRITICAL:** Do NOT introduce new features, refactor unrelated code, or change behavior. Fix only what the issue identified.
6. **Set phase to `test`. End your response.**

---

### test

**Persona:** Read `~/repos/auth/auth-planning/_bmad/bmm/agents/qa.md` — adopt Quinn's mindset.

1. Run full lint: `make lint`
2. Run full unit tests: `make test-unit`
3. Verify:
   - 863+ tests pass (count should be same or higher than before)
   - 80%+ coverage maintained
   - No new warnings
4. If failures: fix and re-run until green. Commit fixes.
5. Record test results in task-state.md under `## Test Results`:
   - Test count
   - Coverage percentage
   - Any notable changes
6. **Set phase to `review-blind`. End your response.**

---

### review-blind

**Persona: Blind Hunter (Adversarial Reviewer)** — Read `~/repos/auth/auth-planning/_bmad/core/skills/bmad-review-adversarial-general/workflow.md`. Cynical, jaded reviewer.

1. Generate the diff: `git diff origin/<base_branch>...HEAD`
2. Review for:
   - Regressions introduced by the changes
   - Incomplete fixes (partially addressed)
   - New edge cases created
   - Missing test coverage for changes
3. Write findings to task-state.md under `## Review: Blind Hunter`:
   ```
   ### MUST FIX
   - [location] finding

   ### SHOULD FIX
   - [location] finding

   ### PASS
   - (if nothing found)
   ```
4. **Set phase to `review-edge`. End your response.**

---

### review-edge

**Persona: Edge Case Hunter** — Read `~/repos/auth/auth-planning/_bmad/core/skills/bmad-review-edge-case-hunter/workflow.md`. Pure path tracer.

1. Generate the diff (same scope)
2. Walk ALL branching paths. Collect ONLY unhandled edge cases.
3. Write findings to task-state.md under `## Review: Edge Case Hunter` as JSON:
   ```json
   [
     {
       "location": "file:line",
       "trigger_condition": "description (max 15 words)",
       "guard_snippet": "minimal code sketch",
       "potential_consequence": "what goes wrong (max 15 words)"
     }
   ]
   ```
   Or `[]` if none found.
4. **Set phase to `review-fix`. End your response.**

---

### review-fix

**Persona:** Amelia (dev.md) — fix mode.

1. Read ALL review sections from task-state.md
2. Fix ALL **MUST FIX** items
3. Fix **SHOULD FIX** and edge cases where the fix is straightforward
4. Run lint and tests after fixes. Commit.
5. If no findings to fix (all PASS): skip to next phase.
6. **Set phase to `pr`. End your response.**

---

### pr

1. Push the branch: `git push origin <branch>`
2. Create PR targeting the **base branch** (not main):
   ```
   gh pr create \
     --base <base_branch> \
     --title "<conventional type>: <description> (#<issue>)" \
     --body "$(cat <<'BODY'
   ## Summary
   <1-3 bullet points describing changes>

   Closes #<issue>

   ## Chained PR
   This PR targets `<base_branch>` (not main). It is part of a quality gate chain:
   Q1 → Q2 → Q3 → Q4 → Q5 → Q6 → Q7 → Q8 → Q9 → Q10

   ## Test Results
   - Tests: <count> passed
   - Coverage: <percentage>%

   ## Review Summary
   <brief summary of review findings and fixes>

   🤖 Generated with [Claude Code](https://claude.com/claude-code)
   BODY
   )"
   ```
   **EXCEPTION for Q1:** Target `main` since `chore/code-quality-audit` is the audit branch.
   Actually, ALL PRs should target `main` for eventual merge, but branches chain locally. Let me clarify:
   - Create PR targeting **main**
   - Note in the PR body that it depends on the previous PR in the chain
3. Record PR URL in task-state.md
4. **Set phase to `ci`. End your response.**

---

### ci

1. Wait for CI: `gh pr checks <pr_number> --repo jamescrowley321/py-identity-model --watch --fail-fast`
   - If timeout, poll up to 3 times with 30s sleep
2. **All pass** → **set phase to `complete`. End your response.**
3. **Fail** → read failure:
   - `gh run list --branch <branch> --repo jamescrowley321/py-identity-model --limit 1`
   - `gh run view <run_id> --repo jamescrowley321/py-identity-model --log-failed`
   - Write details to `## CI` in state file
   - **Set phase to `ci-fix`. End your response.**
4. **No CI** (no checks after 60s) → **set phase to `complete`. End your response.**

---

### ci-fix

1. Read `## CI` from task-state.md
2. Diagnose and fix the failure
3. Run local lint/tests
4. Commit and push: `git push origin <branch>`
5. **Set phase to `ci`. End your response.**

---

### complete

1. Update THIS prompt file: change task status from `pending`/`in_progress` to `done`
2. Update the task queue at `~/repos/auth/auth-planning/_bmad-output/implementation-artifacts/task-queue.md` — add entries for this task to the py-identity-model Quality Gate section
3. Delete `~/repos/auth/py-identity-model/.claude/task-state.md`
4. If more tasks remain, pick up the next one (Step 3)
5. If all tasks done: output <promise>LOOP_COMPLETE</promise>

## Rules

- Execute ONE phase per iteration, then end — do NOT chain phases
- NEVER output a promise unless a task just completed or no tasks remain
- NEVER skip phases — every task goes through all review layers
- **Review integrity:** Each review persona operates independently. Do NOT pre-emptively fix things to avoid review findings.
- NEVER commit to main
- NEVER modify repos other than py-identity-model (except updating task queue in auth-planning)
- Always read ~/repos/auth/CLAUDE.md for repo commands
- **Git conventions:** Use conventional commits (Angular convention). Always work on feature branches.
- **Quality only:** No new features, no scope creep. If you discover something that needs fixing but is out of scope, note it in task-state.md under `## Out of Scope` and move on.
- If stuck multiple iterations on same phase: set task to `blocked`, delete state file, pick up next
- **Chained branches:** Each task branches from the previous task's output. If the previous task's branch doesn't exist on remote, use the local branch. Always `git fetch origin` first.
