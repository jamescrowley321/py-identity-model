"""Pre-minted replay pool for the load/soak suite — TH-1.5 (#474, design §3).

"Pre-mint once, replay many": validation is stateless and real IdPs rate-limit,
so each distinct token class is minted a single time and replayed under load.
Each :class:`PoolEntry` carries the status the booted RS is expected to return
(:data:`~scenarios.EXPECTED_STATUS`), so the Locust driver can score a response
as a failure ONLY when the observed status diverges — expected 401/403 rejections
are the correct outcome and stay out of the error budget (design §5).

The mock-OP forged corpus supplies every forgeable class off a known signing
key; two synthetic classes (``valid_es256``, ``scopeless``) are minted directly
off the mock OP. The ``valid`` class is re-mintable so a long soak can refresh it
across the 300s token TTL (:meth:`LoadPool.refresh`).
"""

from __future__ import annotations

from dataclasses import dataclass
import time
from typing import TYPE_CHECKING

from ..harness.corpus import CORPUS_AUDIENCE, build_corpus
from .scenarios import EXPECTED_STATUS


if TYPE_CHECKING:
    from collections.abc import Iterable

    from ..harness.mock_op import MockOP


# Classes minted directly off the mock OP rather than taken from the forged
# corpus (which is keyed to the RS256 primary key / carries scope="read").
_SYNTHETIC_CLASSES = frozenset({"valid_es256", "scopeless"})

_TOKEN_LIFETIME = 300  # seconds — mirrors the mock OP / real-IdP TTL (design §3)


@dataclass
class PoolEntry:
    """A replayable token plus the RS status its class should produce.

    ``expires_at`` is ``None`` for classes that are not re-minted (forged
    negatives never expire meaningfully — they are already rejected).
    """

    name: str
    token: str
    expected_status: int
    expires_at: float | None = None

    def is_expired(self, *, now: float | None = None, leeway: float = 30.0) -> bool:
        if self.expires_at is None:
            return False
        return (now if now is not None else time.time()) >= self.expires_at - leeway


def _mint_synthetic(op: MockOP, name: str, now: int) -> str:
    """Mint the two classes that are not in the forged corpus."""
    base = {
        "iss": op.issuer,
        "sub": "load-subject",
        "aud": CORPUS_AUDIENCE,
        "iat": now,
        "nbf": now,
        "exp": now + _TOKEN_LIFETIME,
        "client_id": "mock-client",
    }
    if name == "valid_es256":
        # Same valid access token, signed by the published ES256 key — exercises
        # the ES256 validation path for the alg-cost scenario (S2).
        return op.sign({**base, "scope": "read"}, key=op.ec_key)
    if name == "scopeless":
        # Validly signed, no scope/scp and no ID-token-only claim: passes
        # validation, then fails require_scope("read") -> 403.
        return op.sign(base)
    raise ValueError(f"unknown synthetic token class: {name!r}")


class LoadPool:
    """A blend of :class:`PoolEntry` objects for one scenario."""

    def __init__(self, entries: Iterable[PoolEntry], op: MockOP) -> None:
        self._entries = list(entries)
        self._op = op

    @property
    def entries(self) -> list[PoolEntry]:
        return self._entries

    def __len__(self) -> int:
        return len(self._entries)

    def refresh(self, *, now: float | None = None) -> int:
        """Re-mint any expired re-mintable class in place (soak TTL cadence).

        Returns the number of entries re-minted. Forged negatives (``expires_at``
        is ``None``) are never re-minted — they are meant to be rejected.
        """
        stamp = int(now if now is not None else time.time())
        refreshed = 0
        for entry in self._entries:
            if not entry.is_expired(now=now):
                continue
            entry.token = _remint(self._op, entry.name, stamp)
            entry.expires_at = stamp + _TOKEN_LIFETIME
            refreshed += 1
        return refreshed


def _remint(op: MockOP, name: str, now: int) -> str:
    if name == "valid":
        return op.mint_access_token(scopes="read")["access_token"]
    if name in _SYNTHETIC_CLASSES:
        return _mint_synthetic(op, name, now)
    # Forged classes are not re-minted; keep the original token.
    return build_corpus(op)[name].jwt


def build_load_pool(op: MockOP, classes: Iterable[str]) -> LoadPool:
    """Build the replay pool for *classes* off the live mock OP.

    Every requested class must appear in :data:`~scenarios.EXPECTED_STATUS`; an
    unknown class is a scenario-definition bug and raises rather than silently
    dropping load coverage.
    """
    now = int(time.time())
    corpus = build_corpus(op)
    entries: list[PoolEntry] = []
    for name in classes:
        if name not in EXPECTED_STATUS:
            raise ValueError(f"token class {name!r} has no EXPECTED_STATUS mapping")
        if name in _SYNTHETIC_CLASSES:
            token = _mint_synthetic(op, name, now)
        else:
            token = corpus[name].jwt
        # Only the re-mintable valid classes carry an expiry the soak refreshes;
        # forged negatives are already-rejected and need no re-mint.
        remintable = name == "valid" or name in _SYNTHETIC_CLASSES
        entries.append(
            PoolEntry(
                name=name,
                token=token,
                expected_status=EXPECTED_STATUS[name],
                expires_at=now + _TOKEN_LIFETIME if remintable else None,
            )
        )
    return LoadPool(entries, op)
