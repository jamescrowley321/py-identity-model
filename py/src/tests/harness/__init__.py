"""Token-blaster harness shared infrastructure (epic #462, TH-1.1..TH-1.5).

A single home for the pieces T300/T301/T311 share:

* :class:`TokenSource` — the unified multi-provider minter (``mint``) plus the
  pre-minted :class:`ReplayPool`.
* :class:`MockOP` — a controllable, framework-free ASGI OpenID Provider holding
  a known signing key (valid tokens, forged corpus, T311 failure injection).
* :func:`build_corpus` — the forged / negative token corpus.
"""

from __future__ import annotations

from .corpus import CORPUS_AUDIENCE, ForgedToken, build_corpus
from .mock_op import MockOP, MockOPControls, RequestStats, SigningKey
from .mock_op_server import serve_mock_op
from .token_source import (
    Grant,
    HarnessCapabilityError,
    HarnessCredentialError,
    HarnessError,
    Malform,
    MintedToken,
    MintSpec,
    Provider,
    ProviderConfig,
    ReplayPool,
    TokenSource,
    prime_pool,
)


__all__ = [
    "CORPUS_AUDIENCE",
    "ForgedToken",
    "Grant",
    "HarnessCapabilityError",
    "HarnessCredentialError",
    "HarnessError",
    "Malform",
    "MintSpec",
    "MintedToken",
    "MockOP",
    "MockOPControls",
    "Provider",
    "ProviderConfig",
    "ReplayPool",
    "RequestStats",
    "SigningKey",
    "TokenSource",
    "build_corpus",
    "prime_pool",
    "serve_mock_op",
]
