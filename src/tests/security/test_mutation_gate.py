"""Self-test for the mutation-security gate driver (tools/mutation_security.py).

The gate is itself security-critical infrastructure, so its classification logic
is unit-tested here. In particular this locks in the fail-CLOSED inversion: any
mutmut status other than ``killed`` (notably ``no tests`` — a changed line with
zero covering tests) MUST be treated as a survivor. The previous denylist
implementation was fail-open on exactly that status.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


_DRIVER = Path(__file__).resolve().parents[3] / "tools" / "mutation_security.py"
if not _DRIVER.exists():
    # Inside mutmut's mutants/ sandbox, tools/ is not copied. This self-test is
    # meta (it exercises the gate driver, not the mutated security modules), so
    # skip the whole module there rather than failing mutmut's stats collection.
    pytest.skip(
        "mutation_security driver not present (mutmut sandbox)",
        allow_module_level=True,
    )
_spec = importlib.util.spec_from_file_location("mutation_security", _DRIVER)
assert _spec is not None
assert _spec.loader is not None
mutation_security = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mutation_security)

# One mutant name per mutmut status, to exercise the full classification.
_M = "py_identity_model.core.mtls.x_verify__mutmut_"
_SAMPLE_RESULTS = f"""
To apply a mutant on disk:
    mutmut apply <id>

{_M}1: killed
    {_M}2: survived
    {_M}3: no tests
    {_M}4: skipped
    {_M}5: timeout
    {_M}6: suspicious
    {_M}7: killed
some other summary line that is not a mutant
"""
_EXPECTED_STATUSES = {
    f"{_M}1": "killed",
    f"{_M}2": "survived",
    f"{_M}3": "no tests",
    f"{_M}4": "skipped",
    f"{_M}5": "timeout",
    f"{_M}6": "suspicious",
    f"{_M}7": "killed",
}


def test_parse_results_only_captures_mutant_lines():
    assert mutation_security.parse_results(_SAMPLE_RESULTS) == _EXPECTED_STATUSES


def test_only_killed_passes_everything_else_is_a_survivor():
    unwaived, waived = mutation_security.evaluate(_EXPECTED_STATUSES, allowlist=set())
    assert waived == []
    # Every non-killed status is a survivor — including "no tests" (the fail-open
    # the old denylist missed); killed mutants are never reported.
    assert unwaived == [
        f"{_M}2: survived",
        f"{_M}3: no tests",
        f"{_M}4: skipped",
        f"{_M}5: timeout",
        f"{_M}6: suspicious",
    ]


def test_exact_name_allowlist_waives_only_that_mutant():
    unwaived, waived = mutation_security.evaluate(_EXPECTED_STATUSES, {f"{_M}2"})
    assert waived == [f"{_M}2: survived"]
    assert unwaived == [
        f"{_M}3: no tests",
        f"{_M}4: skipped",
        f"{_M}5: timeout",
        f"{_M}6: suspicious",
    ]


def test_allowlist_is_anchored_not_substring():
    # A waiver for one mutant must NOT waive a different mutant whose name
    # contains it as a substring.
    statuses = {"pkg.x_f__mutmut_1": "survived", "pkg.x_f__mutmut_11": "survived"}
    unwaived, waived = mutation_security.evaluate(statuses, {"pkg.x_f__mutmut_1"})
    assert waived == ["pkg.x_f__mutmut_1: survived"]
    assert unwaived == ["pkg.x_f__mutmut_11: survived"]


def test_load_allowlist_strips_comments_and_blanks():
    text = "# a comment\n\npkg.x_a__mutmut_1  # equivalent\n  \npkg.x_b__mutmut_2\n"
    assert mutation_security.load_allowlist(text) == {
        "pkg.x_a__mutmut_1",
        "pkg.x_b__mutmut_2",
    }
