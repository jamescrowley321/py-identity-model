"""Scope-filtered commit parsers for the monorepo's two release pipelines.

The repo hosts two independently versioned distributions:

- the core ``py-identity-model`` library, released by the root
  python-semantic-release config (bare ``{version}`` tags), and
- the ``fastapi-identity-model`` package, released by the config in
  ``packages/fastapi-identity-model/pyproject.toml``
  (``fastapi-identity-model-v{version}`` tags).

python-semantic-release has no native per-package commit routing — every
parsed ``feat``/``fix``/``perf`` commit drives whichever pipeline parses it.
These parsers split the commit stream by conventional-commit scope so each
pipeline only sees its own history:

- :class:`CoreCommitParser` (root pipeline) drops ``(fastapi)``-scoped
  commits, so ``feat(fastapi): ...`` never bumps the core library.
- :class:`FastapiCommitParser` (package pipeline) keeps ONLY
  ``(fastapi)``-scoped commits.

The split is scope-based, not path-based: an unscoped ``fix:`` that touches
only ``packages/`` still bumps the core. Scoping package commits ``(fastapi)``
remains load-bearing — see CLAUDE.md "Workspace Packages".
"""

from __future__ import annotations

from semantic_release.commit_parser.conventional import ConventionalCommitParser
from semantic_release.commit_parser.token import (
    ParsedCommit,
    ParseError,
    ParseResult,
)


PACKAGE_SCOPE = "fastapi"


def _is_package_commit(result: ParseResult) -> bool:
    """Whether a parse result belongs to the fastapi-identity-model package."""
    return isinstance(result, ParsedCommit) and result.scope == PACKAGE_SCOPE


class _ScopeRoutedParser(ConventionalCommitParser):
    """Conventional parser that keeps or drops package-scoped commits."""

    #: subclasses set this: True keeps ONLY package commits, False drops them
    keep_package_scope = True

    def _route(self, result: ParseResult) -> ParseResult:
        if isinstance(result, ParseError):
            return result
        if _is_package_commit(result) == self.keep_package_scope:
            return result
        other = "core" if self.keep_package_scope else "fastapi-identity-model"
        return ParseError(
            commit=result.commit,
            error=f"commit belongs to the {other} release pipeline; ignored here",
        )

    def parse(self, commit) -> ParseResult | list[ParseResult]:
        parsed = super().parse(commit)
        if isinstance(parsed, list):
            return [self._route(result) for result in parsed]
        return self._route(parsed)


class CoreCommitParser(_ScopeRoutedParser):
    """Root pipeline: everything except ``(fastapi)``-scoped commits."""

    keep_package_scope = False


class FastapiCommitParser(_ScopeRoutedParser):
    """Package pipeline: ONLY ``(fastapi)``-scoped commits."""

    keep_package_scope = True
