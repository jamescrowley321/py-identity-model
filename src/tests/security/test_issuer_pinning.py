"""Fail-closed tests for multi-tenant issuer pinning (SC2 / Epic 16 R.9).

Audit RT-SPOOF-F1: the library validated the token's ``iss`` against whatever
discovery document the caller pointed at, with no approved-issuer allowlist. A
caller that resolves discovery from the untrusted token's ``iss`` (the idiomatic
multi-tenant pattern) would therefore accept a validly-signed token from an
attacker's own tenant. ``allowed_issuers`` pins the approved set and is enforced
before the discovery result is trusted.

Each test fails if the control is reverted:
* ``decode_with_config`` (the shared chokepoint for every path) rejects an
  effective issuer outside the allowlist;
* ``build_resolved_config`` propagates ``allowed_issuers`` — without this the
  discovery/retry paths (which validate via the resolved config) would silently
  skip the check;
* the ``_enforce_allowed_issuers`` logic fails closed on the edge cases.
"""

from __future__ import annotations

import jwt as pyjwt
import pytest

from py_identity_model.core.models import TokenValidationConfig
from py_identity_model.core.token_validation_logic import (
    _enforce_allowed_issuers,
    build_resolved_config,
    decode_with_config,
)
from py_identity_model.exceptions import InvalidIssuerException


_LEGIT = "https://api.descope.com/v1/apps/LEGIT"
_ATTACKER = "https://api.descope.com/v1/apps/ATTACKER"


class TestChokepointRejectsUnapprovedIssuer:
    def test_attacker_tenant_issuer_rejected_before_decode(self):
        # The exact multi-tenant attack: discovery resolved to the attacker's own
        # tenant issuer. Even with a well-formed key/alg, pinning rejects it
        # before the token is decoded/trusted.
        cfg = TokenValidationConfig(
            perform_disco=True,
            key={"kty": "RSA"},
            algorithms=["RS256"],
            allowed_issuers=[_LEGIT],
        )
        with pytest.raises(
            InvalidIssuerException, match="not in the configured allowed_issuers"
        ):
            decode_with_config("a.b.c", cfg, issuer=_ATTACKER)

    def test_default_no_allowlist_does_not_pin(self):
        # OPT-IN: with allowed_issuers unset (the default), discovery stays
        # authoritative — no pinning. Decode proceeds past the (absent) issuer
        # check and fails downstream on the dummy token/key for an unrelated
        # reason — never with InvalidIssuerException. Locks in that this control
        # does not change default behaviour.
        cfg = TokenValidationConfig(
            perform_disco=True, key={"kty": "RSA"}, algorithms=["RS256"]
        )
        # The flow reaches decode (past the skipped pin) and fails there building
        # PyJWK from the dummy key — a jwt InvalidKeyError, NOT the
        # InvalidIssuerException pinning would raise. If pinning were not opt-in,
        # InvalidIssuerException would be raised first and this would fail.
        with pytest.raises(pyjwt.InvalidKeyError):
            decode_with_config("a.b.c", cfg, issuer=_ATTACKER)


class TestResolvedConfigPropagatesAllowlist:
    def test_build_resolved_config_carries_allowed_issuers(self):
        # Without propagation the disco/retry paths validate via a resolved config
        # whose allowed_issuers is None -> the pin is silently skipped on the main
        # attack path. This test locks the propagation in.
        cfg = TokenValidationConfig(perform_disco=True, allowed_issuers=[_LEGIT])
        resolved = build_resolved_config(cfg, {"kty": "RSA"}, "RS256")
        assert resolved.allowed_issuers == [_LEGIT]


class TestEnforceAllowedIssuers:
    def test_allowed_single_issuer_passes(self):
        _enforce_allowed_issuers(_LEGIT, [_LEGIT])  # no raise

    def test_disallowed_single_issuer_rejected(self):
        with pytest.raises(
            InvalidIssuerException, match="not in the configured allowed_issuers"
        ):
            _enforce_allowed_issuers(_ATTACKER, [_LEGIT])

    def test_list_all_allowed_passes(self):
        _enforce_allowed_issuers(
            [_LEGIT, "https://other/LEGIT2"], [_LEGIT, "https://other/LEGIT2"]
        )

    def test_list_with_one_disallowed_rejected(self):
        with pytest.raises(InvalidIssuerException):
            _enforce_allowed_issuers([_LEGIT, _ATTACKER], [_LEGIT])

    def test_unresolvable_issuer_fails_closed(self):
        # allowed_issuers configured but nothing resolved to check -> reject,
        # never skip the check.
        with pytest.raises(InvalidIssuerException, match="no issuer was resolved"):
            _enforce_allowed_issuers(None, [_LEGIT])
