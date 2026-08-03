"""Fail-closed tests for algorithm confusion / downgrade (SC1 / Epic 16 R.1).

Each test asserts a control the 2026-08-02 audit found missing (RT4-F1/F2) and
fails if that control is reverted:

* the caller's ``algorithms`` allowlist is honoured in discovery mode
  (``build_resolved_config`` — the stranded F0 guard);
* the library's own key/alg-consistency check rejects RS->HS confusion and
  ``alg=none`` (not left to PyJWT);
* the signing algorithm is resolved from the trusted key material, never the
  attacker-controlled token header.
"""

from __future__ import annotations

import pytest

from py_identity_model.core.models import JsonWebKey, TokenValidationConfig
from py_identity_model.core.parsers import (
    _validate_key_alg_consistency,
    find_key_by_kid,
)
from py_identity_model.core.token_validation_logic import build_resolved_config
from py_identity_model.exceptions import TokenValidationException


def _rsa_key(kid: str = "k1", alg: str | None = None) -> JsonWebKey:
    # Minimal RSA JWK; the confusion check runs on kty before key material.
    return JsonWebKey(kty="RSA", kid=kid, alg=alg, n="abc", e="AQAB", use="sig")


def _ec_key(kid: str = "k1", crv: str = "P-256", alg: str | None = None) -> JsonWebKey:
    return JsonWebKey(kty="EC", kid=kid, alg=alg, crv=crv, x="x", y="y", use="sig")


class TestAllowlistHonoured:
    def test_resolved_alg_not_in_caller_allowlist_is_rejected(self):
        # Caller restricts to ES256; a token resolved to RS256 must be refused —
        # the downgrade the FAPI 2.0 profile forbids (audit F0 / RT4-F1).
        cfg = TokenValidationConfig(perform_disco=True, algorithms=["ES256"])
        with pytest.raises(
            TokenValidationException, match="not in the caller's allowed"
        ):
            build_resolved_config(cfg, {"kty": "RSA"}, "RS256")

    def test_resolved_alg_in_caller_allowlist_is_accepted(self):
        cfg = TokenValidationConfig(perform_disco=True, algorithms=["RS256", "ES256"])
        resolved = build_resolved_config(cfg, {"kty": "RSA"}, "RS256")
        assert resolved.algorithms == ["RS256"]

    def test_no_caller_allowlist_allows_resolved_alg(self):
        cfg = TokenValidationConfig(perform_disco=True, algorithms=None)
        resolved = build_resolved_config(cfg, {"kty": "RSA"}, "RS256")
        assert resolved.algorithms == ["RS256"]


class TestConfusionRejectedByLibrary:
    def test_rs_to_hs_confusion_rejected(self):
        # HS256 token verified against an RSA key (public key as HMAC secret):
        # the library's own check must reject it, not defer to PyJWT.
        with pytest.raises(TokenValidationException):
            _validate_key_alg_consistency(_rsa_key(), "HS256")

    def test_alg_none_rejected(self):
        with pytest.raises(TokenValidationException, match="alg=none"):
            _validate_key_alg_consistency(_rsa_key(), "none")

    def test_rs_to_hs_confusion_rejected_via_key_lookup(self):
        with pytest.raises(TokenValidationException):
            find_key_by_kid("k1", [_rsa_key()], jwt_alg="HS256")


class TestAlgResolvedFromKeyNotHeader:
    def test_ec_key_without_alg_resolves_from_curve_not_blanket_rs256(self):
        # A P-256 EC key with no `alg` must resolve to ES256 (from the key), not
        # the old blanket RS256, and not the token header.
        _key, alg = find_key_by_kid("k1", [_ec_key(crv="P-256")], jwt_alg=None)
        assert alg == "ES256"

    def test_rsa_key_without_alg_defaults_to_rs256(self):
        # No declared alg and no header: default to the key-type default (RS256
        # for RSA), never leaving the alg unresolved. (Header-driven key-type
        # confusion is covered by test_rs_to_hs_confusion_rejected.)
        _key, alg = find_key_by_kid(None, [_rsa_key(alg=None)], jwt_alg=None)
        assert alg == "RS256"
