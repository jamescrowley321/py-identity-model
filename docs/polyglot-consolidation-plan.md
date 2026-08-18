# Polyglot Consolidation Plan — `identity-model` → `py-identity-model`

**Status:** Design of record. Decided 2026-08-17 (James). Supersedes the prior
"PIM into the polyglot monorepo" direction (see _Reversal_ below).

## Decision

Move `jamescrowley321/identity-model` (Go + Rust) **into**
`jamescrowley321/py-identity-model` (PIM). **PIM is the surviving repo** — it keeps
its git history, release tags, OIDF certification, and PyPI pipelines.
`identity-model`'s history is expendable (0 tags, never released, not prod-ready).
Package naming stays `{py,go,rs}-identity-model` at the package level even though the
repo is `py-identity-model`.

## Reversal — why this inverts the prior plan

The earlier decision (2026-08-01, reaffirmed 2026-08-12 in PR #72) was the opposite:
move PIM **into** `identity-model` because that repo was the purpose-built polyglot
shell (`spec/` + `infra/` + capabilities matrix) and "merging into it is less work."

That plan would have moved the **certified, PyPI-published, 329-tag** artifact (PIM)
into a **0-tag** shell — disrupting exactly the cert lineage + release pipelines the
same memo flagged as the thing to protect. Keeping PIM stationary as the survivor:

- **OIDF cert continuity → non-issue.** The certified software and its `conformance/`
  submission artifacts don't move; the mark is unaffected.
- **PyPI pipelines untouched.** `py-identity-model` + `fastapi-identity-model`
  semantic-release stay exactly where they are.
- **Minimal structural reshaping.** PIM is already a uv monorepo
  (`pyproject.toml` `members = [".", "packages/fastapi-identity-model", …]` with a split
  semantic-release), so `go/` and `rust/` are natural siblings.

### What the reversal trades away (accepted)

1. **Re-homing the polyglot shell.** `identity-model`'s `spec/` neutral-vector
   conformance contract, `infra/` shared IdP fixtures, and paths-filtered Go/Rust CI
   must be ported **into** PIM rather than inherited for free. This is the real work.
2. **Go import-path break.** `github.com/jamescrowley321/identity-model/go` →
   `github.com/jamescrowley321/py-identity-model/go`. Accepted (0 consumers, not prod);
   document in `go/README.md` + CHANGELOG.
3. **Stale planning artifacts.** PR #72's docs
   (`docs/identity-model-reconciliation-2026-08-12.md`, roadmap PRD, `epic-20-pim-parity`)
   now describe the opposite direction and need an update pass (P3).

## Surviving hard constraint (carried forward)

Do **not** duplicate internal conformance vectors across the three languages. Build
them **once**: language-neutral vectors + fixtures + expected outcomes keyed on
canonical error codes (not per-language type names) in `spec/`; a **thin per-language
executor** mapping vectors → that language's API/errors; a **coverage gate** (every
language executes every vector id). Port `identity-model`'s `spec/` in; add PIM's
Python thin executor onto the same vectors.

PIM's external OIDF-cert `conformance/` harness is a **different kind** of testing
(black-box certification vs. white-box internal vectors) — keep it; it is not the
duplication being removed.

## Target layout (in `py-identity-model`)

```
src/                    # Python core — unchanged
packages/fastapi-…      # existing sub-package — unchanged
go/                     # from identity-model; module → …/py-identity-model/go
rust/                   # from identity-model; crate rs-identity-model — unchanged
spec/                   # from identity-model — neutral vectors, single source of conformance truth
infra/                  # MERGE identity-model infra/ + PIM test-fixtures/ → one IdP fixture set
conformance/            # PIM OIDF cert harness — unchanged; identity-model rp-go runner folded in
src/tests/harness/      # existing Python harness → thin executor onto spec/ vectors
```

## Release & CI — independent cadence per language

- **Python:** existing semantic-release → PyPI, **unchanged**. Add path-ignore guards so
  commits touching only `go/**`, `rust/**`, `spec/**`, `infra/**` never cut a PyPI
  release. (The core parser already excludes `(fastapi)`-scoped commits; this extends the
  same principle by path.)
- **Go:** GoReleaser/tags workflow, path-filtered `go/**`. First release is greenfield.
- **Rust:** cargo-release → crates.io, path-filtered `rust/**`.
- **Change-detection:** `dorny/paths-filter` so only affected language suites run; bring
  the docker IdP fixture matrix up **once**, shared across suites.
- **Secrets:** consolidate DESCOPE mgmt key, conformance token, PyPI/crates OIDC publish
  into the one repo's secrets.

## Migration mechanic

`identity-model`'s blame is expendable, so **no `git-filter-repo`/subtree gymnastics**.
Bring its tree in as new files in ordinary commits on PIM. (A one-time `git subtree add`
remains available if we ever decide IM history is worth keeping — not required.)

## Phased PRs (stacked into `py-identity-model`, merged bottom-up)

- **P0 — this brief** as design of record. `docs:` (release-safe).
- **P1 — land the code.** Add `go/` + `rust/` + `spec/` trees; add path-filtered Go +
  Rust CI; document the Go module-path rename. Guard the Python release on paths.
  Verify: `go build/test` + `cargo test` green in-repo; a dry-run confirms no accidental
  PyPI release from a `go/`/`rust/` commit.
- **P2 — dedup fixtures.** Merge `identity-model` `infra/` + PIM `test-fixtures/` into one
  fixture set; wire the Python thin executor onto `spec/` vectors; enforce the coverage
  gate. This is the dedup payoff.
- **P3 — retire the old repo.** Archive `jamescrowley321/identity-model` read-only with a
  README pointer to PIM; repoint ralph loops / `PROMPT.md`; update the stale PR-#72
  planning artifacts.

## Sequencing vs. in-flight work

- PIM `main` is quiescent (just merged #532) — a good window to land P1 as one PR.
- `identity-model`'s active Rust-Extended loop + K3–K6 conformance and PIM's #476 FAPI2
  epic must pause/rebase onto the new paths. Coordinate a short freeze: land P1 + P2, then
  relaunch loops pointed at `py-identity-model/{go,rust,spec}`.
- PIM #462 E2E harness is largely delivered → low collision risk.

## Risk register

| Risk | Mitigation |
|---|---|
| Re-homing `spec/` + `infra/` + CI is the real cost | Isolated in P2; P1 lands code first so surface stays small |
| Accidental PyPI release from a `go/`/`rust/` commit | Path-guard `release.yml`; dry-run tag before first real go/rust release |
| Go consumers break on module-path change | None in prod (0 tags); documented in `go/README` + CHANGELOG |
| Stale PR-#72 planning artifacts mislead a future session | Memory updated now; artifacts corrected in P3 |
| Active loops strand on old paths | Freeze window; relaunch against new paths after P2 |

## Open questions for the owner

1. **`spec/` as the one conformance source** — confirm Python's thin executor drops onto
   `identity-model`'s existing neutral vectors (vs. keeping PIM's current fixtures as-is
   and only sharing docker IdP infra).
2. **Do P1–P3 in-session as a stacked PR set**, or hand to a ralph loop? (Reversal is
   well-scoped → in-session stacking is viable.)
3. **Retire vs. keep `identity-model`** as a thin read-only mirror after P3.
