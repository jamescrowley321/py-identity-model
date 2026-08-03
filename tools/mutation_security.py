#!/usr/bin/env python3
"""Changed-files-scoped mutation gate for the security-critical modules.

Epic 19 G.1 (mutation gate) + G.5 (aggregate ``security-gate``). This driver
runs `mutmut <https://github.com/boxed/mutmut>`_ against **only** the
security-critical modules that changed versus ``BASE`` (default ``origin/main``)
and fails if any mutant that is **not provably killed** survives.

Why "not killed = survivor" (fail-closed), not a denylist
---------------------------------------------------------
An earlier version enumerated a *denylist* of survivor statuses
(``survived``/``timeout``/...). That is **fail-open**: mutmut also emits
``no tests`` (a changed line with zero covering tests), ``skipped``,
``suspicious`` and future statuses — none of which were on the denylist, so a
control with no test at all was silently reported as PASSED. We invert it: the
**only** passing status is ``killed``; every other status is a survivor unless
it is explicitly waived. This is robust to new mutmut statuses by construction.

Guardrails
----------
* **Changed-files scope, not full-tree.** Full mutation of every security module
  is a nightly concern; on a PR we prove the *files this PR touched* are pinned
  by fail-closed tests. Empty intersection -> exit 0 (safe as a required check).
* **>=1-mutant floor.** If mutmut produced **zero** mutants for the changed
  files, that is a config/scope/version-drift failure, not a pass — we exit 1.
  (This is the "silent green on output drift" hole the review flagged.)
* **Exact-name equivalent-mutant allowlist.** Genuinely-equivalent mutants
  (semantically identical, unkillable) are waived by their **exact mutant name**
  in ``tools/mutation_security_allowlist.txt`` (anchored, not substring-anywhere
  — one broad substring must never silently waive real survivors elsewhere).

mutmut 3.x is configured via ``setup.cfg [mutmut]``; this driver writes a
**temporary** ``setup.cfg`` for the run (restoring any pre-existing one) so the
scope stays dynamic. ``also_copy = src/tests`` is required because this repo's
tests live under ``src/tests`` (mutmut only auto-copies top-level ``tests/``).
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import sys


# ── The security-critical surface ────────────────────────────────────────────
# Every module here is mutation-gated when it changes. Keep in sync with
# docs/security/control-matrix.md. Broad on purpose: changed-files scoping means
# only the files a PR *touches* are actually mutated, so listing the whole
# security surface costs nothing until one of them changes.
SECURITY_MODULES: list[str] = [
    # core validation / crypto / protocol
    "src/py_identity_model/core/token_validation_logic.py",
    "src/py_identity_model/core/jwt_helpers.py",
    "src/py_identity_model/core/parsers.py",
    "src/py_identity_model/core/mtls.py",
    "src/py_identity_model/core/dpop.py",
    "src/py_identity_model/core/jarm.py",
    "src/py_identity_model/core/client_auth.py",
    "src/py_identity_model/core/jwks_logic.py",
    "src/py_identity_model/core/jwks_cache.py",
    "src/py_identity_model/core/discovery_logic.py",
    "src/py_identity_model/core/discovery_policy.py",
    "src/py_identity_model/core/state_validation.py",
    "src/py_identity_model/core/validators.py",
    # public entrypoint wrappers (sync + aio) — where controls must be *invoked*
    "src/py_identity_model/sync/token_validation.py",
    "src/py_identity_model/sync/userinfo.py",
    "src/py_identity_model/sync/logout.py",
    "src/py_identity_model/aio/token_validation.py",
    "src/py_identity_model/aio/userinfo.py",
    "src/py_identity_model/aio/logout.py",
]

# Package root copied (and made importable) into mutmut's ``mutants/`` sandbox.
SOURCE_ROOT = "src/py_identity_model"

# Tests mutmut may run to kill mutants. mutmut narrows this per-mutant to the
# covering tests via its stats-collection pass, so listing the suite does not
# mean every test runs for every mutant.
TEST_SELECTION: list[str] = ["src/tests/security", "src/tests/unit"]

ALLOWLIST_FILE = Path("tools/mutation_security_allowlist.txt")

# The ONLY status that counts as a killed mutant. Everything else is a survivor.
KILLED_STATUS = "killed"

# mutmut mutant names always contain this marker.
_MUTANT_LINE = re.compile(
    r"^\s*(?P<name>\S*__mutmut_\S*):\s*(?P<status>[a-z][a-z ]*?)\s*$"
)


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    # Commands are built from module constants and a git ref, never untrusted
    # shell input; shell=False keeps args literal.
    return subprocess.run(cmd, text=True, capture_output=True, check=False)  # noqa: S603


def changed_security_files(base: str) -> list[str]:
    """Security modules changed on HEAD versus ``base`` (that still exist)."""
    res = _run(["git", "diff", "--name-only", f"{base}...HEAD"])
    if res.returncode != 0:
        # No common merge-base yet (e.g. a freshly created local base branch):
        # fall back to a direct two-dot diff against the base tip.
        res = _run(["git", "diff", "--name-only", base])
    if res.returncode != 0:
        print(
            f"error: could not diff against BASE={base!r}:\n{res.stderr}",
            file=sys.stderr,
        )
        sys.exit(2)
    changed = set(res.stdout.split())
    return [m for m in SECURITY_MODULES if m in changed and Path(m).exists()]


def _write_setup_cfg(only_mutate: list[str]) -> str | None:
    """Write a temporary ``setup.cfg`` for the run; return backup text if any."""
    cfg = Path("setup.cfg")
    backup = cfg.read_text() if cfg.exists() else None
    only_block = "\n".join(f"    {p}" for p in only_mutate)
    test_block = "\n".join(f"    {p}" for p in TEST_SELECTION)
    cfg.write_text(
        "[mutmut]\n"
        f"source_paths = {SOURCE_ROOT}\n"
        f"only_mutate =\n{only_block}\n"
        # This repo's tests live under src/tests; mutmut only auto-copies
        # top-level tests/, so without this the sandbox has no tests to run.
        "also_copy =\n    src/tests\n"
        f"pytest_add_cli_args_test_selection =\n{test_block}\n"
    )
    return backup


def _restore_setup_cfg(backup: str | None) -> None:
    cfg = Path("setup.cfg")
    if backup is None:
        cfg.unlink(missing_ok=True)
    else:
        cfg.write_text(backup)


def load_allowlist(text: str) -> set[str]:
    """Exact mutant names to waive (equivalent mutants). One name per line;
    ``#`` comments and blanks ignored."""
    return {
        stripped
        for line in text.splitlines()
        if (stripped := line.split("#", 1)[0].strip())
    }


def parse_results(text: str) -> dict[str, str]:
    """Map ``mutant-name -> status`` from ``mutmut results --all`` output.

    Only lines naming a real mutant (``...__mutmut_N``) are parsed; headers and
    summary lines are ignored.
    """
    statuses: dict[str, str] = {}
    for line in text.splitlines():
        m = _MUTANT_LINE.match(line)
        if m:
            statuses[m.group("name")] = m.group("status")
    return statuses


def evaluate(
    statuses: dict[str, str], allowlist: set[str]
) -> tuple[list[str], list[str]]:
    """Return ``(unwaived_survivors, waived_survivors)``.

    A survivor is **any** mutant whose status is not exactly ``killed``.
    """
    unwaived, waived = [], []
    for name, status in sorted(statuses.items()):
        if status == KILLED_STATUS:
            continue
        (waived if name in allowlist else unwaived).append(f"{name}: {status}")
    return unwaived, waived


def _mutmut_results_text() -> str:
    # --all so killed mutants are included too (needed for the >=1 floor check).
    return _run([sys.executable, "-m", "mutmut", "results", "--all", "true"]).stdout


def main() -> int:
    base = os.environ.get("BASE", "origin/main")
    changed = changed_security_files(base)

    if not changed:
        print(
            f"mutation-security: no security modules changed vs {base}; gate is a no-op pass."
        )
        return 0

    print(
        f"mutation-security: gating {len(changed)} changed security module(s) vs {base}:"
    )
    for f in changed:
        print(f"  - {f}")

    backup = _write_setup_cfg(changed)
    try:
        # mutmut writes into ./mutants (gitignored) and exits 0 even with survivors;
        # a non-zero code means the run itself crashed (bad config, import error...).
        run = subprocess.run(  # noqa: S603
            [sys.executable, "-m", "mutmut", "run"], check=False, text=True
        )
        if run.returncode != 0:
            print("mutation-security: mutmut run failed to complete.", file=sys.stderr)
            return 2

        statuses = parse_results(_mutmut_results_text())

        # >=1-mutant floor: zero mutants for changed files == config/version drift,
        # not a pass. Without this, output-format drift would be a silent green.
        if not statuses:
            print(
                "mutation-security: FAILED — mutmut produced 0 mutants for the changed "
                "security module(s). This is config/scope/version drift, not a pass.",
                file=sys.stderr,
            )
            return 2

        unwaived, waived = evaluate(statuses, load_allowlist(_read_allowlist()))
        for w in waived:
            print(f"mutation-security: WAIVED equivalent mutant {w}")

        if unwaived:
            print(
                "\nmutation-security: FAILED — surviving mutant(s) with no fail-closed test:"
            )
            for s in unwaived:
                print(f"  {s}")
            print(
                "\nAdd a test under src/tests/security/ that kills the mutant "
                "(`mutmut show <name>` to see it), or — if it is provably equivalent — "
                "waive its exact name in tools/mutation_security_allowlist.txt with a justification."
            )
            return 1

        print(
            f"mutation-security: PASSED — {len(statuses)} mutant(s) across the changed "
            "security module(s), all killed (or waived-equivalent)."
        )
        return 0
    finally:
        _restore_setup_cfg(backup)


def _read_allowlist() -> str:
    return ALLOWLIST_FILE.read_text() if ALLOWLIST_FILE.exists() else ""


if __name__ == "__main__":
    raise SystemExit(main())
