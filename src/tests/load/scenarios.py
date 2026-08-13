"""Load/soak scenario catalogue — TH-1.5 (#474 · epic #462, design §4 S1-S12).

Each :class:`Scenario` is *data*: which token classes populate the replay pool,
what mock-OP failure injection to apply before the run, how much load to drive,
and which SLO gate (design §5) evaluates the result. The :mod:`runner` executes
a scenario; :mod:`pool` builds its token blend; :mod:`locustfile` drives it.

Scenarios are grouped into run **profiles**:

* ``CI_SHORT`` (S1-S8) — the PR gate: short, deterministic, mock-OP-backed,
  self-contained (no Docker).
* ``DIAGNOSTIC`` (S5, S9, S10) — head-of-line / no-store / blocking-validator
  probes run on demand.
* ``NIGHTLY`` (S7, S11, S12) — long LRU-thrash / RSS-FD soak / multi-tenant runs.

The SLO gate *thresholds* start unset (:mod:`runner` ``GATES``); the ``test``
phase runs a baseline, and the ``docs`` phase writes the calibrated table into
``README.md``. Until then the gates are permissive so a baseline run never fails
on an uncalibrated threshold.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from ..harness.mock_op import MockOP


# HTTP status codes the RS returns for each token class (audience=mock-api,
# require_scope=read — the same RS contract the correctness matrix asserts).
HTTP_OK = 200
HTTP_UNAUTHORIZED = 401
HTTP_FORBIDDEN = 403


# Token class -> the status the booted RS returns in STEADY STATE (no failure
# injection). Validly signed, correctly scoped tokens reach ``/protected`` (200);
# every validation-failure class collapses to a uniform 401 (F-18); the
# ID-token-as-access class is rejected by the always-on F-07 negative defence;
# the scope-less token validates but fails ``require_scope`` (403).
EXPECTED_STATUS: dict[str, int] = {
    "valid": HTTP_OK,
    "valid_es256": HTTP_OK,
    "cnf_bound": HTTP_OK,
    "oversized": HTTP_OK,
    "multi_aud_untrusted": HTTP_OK,
    "id_as_access": HTTP_UNAUTHORIZED,
    "expired": HTTP_UNAUTHORIZED,
    "nbf_future": HTTP_UNAUTHORIZED,
    "wrong_iss": HTTP_UNAUTHORIZED,
    "wrong_aud": HTTP_UNAUTHORIZED,
    "tampered_sig": HTTP_UNAUTHORIZED,
    "unknown_kid": HTTP_UNAUTHORIZED,
    "wrong_alg": HTTP_UNAUTHORIZED,
    "alg_none": HTTP_UNAUTHORIZED,
    "scopeless": HTTP_FORBIDDEN,
}

# The eight validation-failure classes whose 401s are the CORRECT outcome, not
# an error — they are excluded from the error budget (design §5). ``id_as_access``
# (401) and ``scopeless`` (403) are expected rejections too, tracked by their own
# expected status above; a class is an error only when observed != expected.
EXPECTED_REJECTION_CLASSES = frozenset(
    {
        "expired",
        "nbf_future",
        "wrong_iss",
        "wrong_aud",
        "tampered_sig",
        "unknown_kid",
        "wrong_alg",
        "alg_none",
        "id_as_access",
        "scopeless",
    }
)

# A representative mixed blend for the rejection-under-contention scenario (S8):
# accepted classes interleaved with every rejection class.
MIXED_CLASSES: tuple[str, ...] = (
    "valid",
    "cnf_bound",
    "oversized",
    "multi_aud_untrusted",
    "id_as_access",
    "expired",
    "nbf_future",
    "wrong_iss",
    "wrong_aud",
    "tampered_sig",
    "unknown_kid",
    "wrong_alg",
    "alg_none",
    "scopeless",
)


class Profile(StrEnum):
    """A named set of scenarios run together."""

    CI_SHORT = "ci-short"
    DIAGNOSTIC = "diagnostic"
    NIGHTLY = "nightly"


# A pre-run hook mutating the mock OP (failure injection) before load starts.
SetupHook = Callable[["MockOP"], None]


@dataclass(frozen=True)
class Scenario:
    """One load/soak scenario (design §4).

    Attributes:
        id: Stable scenario id (``"S1"``…``"S12"``).
        title: Human-readable description.
        profile: The run profile this scenario belongs to.
        classes: Token classes blended into the replay pool.
        users: Concurrent Locust users.
        duration_seconds: How long to hold load.
        setup: Optional mock-OP failure injection applied before the run.
        steady_state: When ``True`` a class observed != its ``EXPECTED_STATUS``
            is an error; when ``False`` (active failure injection) the per-class
            status distribution is *reported* but not asserted, because the
            expected status is transient and calibrated in the ``test`` phase.
        gate: SLO gate key (design §5) or ``None`` while uncalibrated.
        notes: What the scenario proves.
    """

    id: str
    title: str
    profile: Profile
    classes: tuple[str, ...]
    users: int = 8
    duration_seconds: float = 3.0
    setup: SetupHook | None = field(default=None, repr=False)
    steady_state: bool = True
    gate: str | None = None
    notes: str = ""


def _no_store_discovery(op: MockOP) -> None:
    """S9: force the discovery document to be re-fetched on every request."""
    op.controls.discovery_cache_control = "no-store"


def _rotate_unpublished(op: MockOP) -> None:
    """S6: rotate the active signing key WITHOUT publishing it, so freshly
    minted tokens present an unknown ``kid`` until the cooldown recovers."""
    op.rotate_keys(publish=False)


def _inject_latency(op: MockOP) -> None:
    """S5: add upstream latency so a cache-miss fetch stalls the single-flight
    holder (head-of-line blocking)."""
    op.controls.latency_seconds = 0.25


# The scenario catalogue. S1-S8 form CI_SHORT; S9/S10/S5 DIAGNOSTIC; S7/S11/S12
# NIGHTLY. Deep mid-run dynamics (S4 TTL rollover, S6 rotation storm, S11 soak
# RSS/FD trends) are calibrated in the test phase; the setup hooks here apply the
# pre-run failure-injection state each scenario needs.
SCENARIOS: tuple[Scenario, ...] = (
    Scenario(
        id="S1",
        title="warm RPS ceiling (valid RS256, hot cache)",
        profile=Profile.CI_SHORT,
        classes=("valid",),
        gate="warm",
        notes="find the warm p99 knee and RPS/worker with a fully hot cache",
    ),
    Scenario(
        id="S2",
        title="alg cost (RS256 vs ES256, warm)",
        profile=Profile.CI_SHORT,
        classes=("valid", "valid_es256"),
        gate="warm",
        notes="report the ES256/RS256 warm-validation cost ratio",
    ),
    Scenario(
        id="S3",
        title="cold stampede (empty cache, burst)",
        profile=Profile.CI_SHORT,
        classes=("valid",),
        users=16,
        gate="cold",
        notes="a burst against an empty cache must fetch discovery+JWKS once "
        "each (single-flight) — asserted via the mock-OP /_stats counters",
    ),
    Scenario(
        id="S4",
        title="TTL refresh under load (short TTL)",
        profile=Profile.CI_SHORT,
        classes=("valid",),
        gate="warm",
        notes="a cache TTL rollover mid-load must not spike errors or storm "
        "the upstream (single-flight refresh)",
    ),
    Scenario(
        id="S5",
        title="provider-slowness head-of-line blocking",
        profile=Profile.DIAGNOSTIC,
        classes=("valid",),
        setup=_inject_latency,
        steady_state=False,
        gate="cold",
        notes="the single-flight holder retries with backoff while holding the "
        "fetch lock — bound the cohort stall, capture 503-vs-401",
    ),
    Scenario(
        id="S6",
        title="kid-rotation storm + unknown-kid flood",
        profile=Profile.CI_SHORT,
        classes=("valid", "unknown_kid"),
        setup=_rotate_unpublished,
        steady_state=False,
        gate="cold",
        notes="unknown-kid flood must recover within ~1 cooldown, cap upstream "
        "fetches, and 401 cleanly with no 500s",
    ),
    Scenario(
        id="S7",
        title="LRU thrash > 64 issuers",
        profile=Profile.NIGHTLY,
        classes=("valid",),
        duration_seconds=10.0,
        gate="warm",
        notes="bounded memory under > 64 distinct issuers; eviction purges the "
        "single-flight sidecar (calibrated nightly)",
    ),
    Scenario(
        id="S8",
        title="rejection correctness & uniformity under contention",
        profile=Profile.CI_SHORT,
        classes=MIXED_CLASSES,
        users=16,
        gate="warm",
        notes="every class returns its correct status under contention, F-18 "
        "uniform 401 body, F-07 reject, F-02 accepted-today, ZERO 500s",
    ),
    Scenario(
        id="S9",
        title="discovery no-store (re-fetch every request)",
        profile=Profile.DIAGNOSTIC,
        classes=("valid",),
        setup=_no_store_discovery,
        steady_state=False,
        gate="cold",
        notes="no-store discovery collapses throughput (re-fetch per request) "
        "while JWKS stays cached",
    ),
    Scenario(
        id="S10",
        title="blocking claims_validator (event-loop stall)",
        profile=Profile.DIAGNOSTIC,
        classes=("valid",),
        steady_state=False,
        gate="warm",
        notes="a synchronous custom claims validator stalls the loop vs an "
        "async one (calibrated in the test phase)",
    ),
    Scenario(
        id="S11",
        title="RSS / FD soak",
        profile=Profile.NIGHTLY,
        classes=("valid",),
        duration_seconds=30.0,
        gate="warm",
        notes="flat RSS/FD for a single issuer; bounded churn at 64 issuers "
        "(calibrated nightly)",
    ),
    Scenario(
        id="S12",
        title="multi-tenant + issuer mix-up",
        profile=Profile.NIGHTLY,
        classes=("valid", "wrong_iss"),
        gate="warm",
        notes="dct/tenants LRU survival (TH-2.1) + RFC 9207 cross-issuer "
        "rejection (TH-2.2) under load (calibrated nightly)",
    ),
)

# id -> Scenario, for lookup by the runner and tests.
SCENARIOS_BY_ID: dict[str, Scenario] = {s.id: s for s in SCENARIOS}


def profile_scenarios(profile: Profile) -> list[Scenario]:
    """The scenarios that belong to *profile*, in catalogue order."""
    return [s for s in SCENARIOS if s.profile is profile]
