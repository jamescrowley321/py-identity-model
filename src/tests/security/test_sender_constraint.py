"""Fail-closed tests for RS-side sender-constraint + strict audience (SC3, Epic 16 R.2).

Audit RT1-F1 (mTLS cert-binding never enforced) and RT5-F18 (secondary-audience
gap). Both controls are OPT-IN — default behaviour is unchanged — and fail closed
only when the caller asks for them. DPoP ``cnf.jkt`` resource-server verification
is a separate, larger feature tracked as #478 and intentionally out of scope here.

Each test fails if its control is reverted.
"""

from __future__ import annotations

import pytest

import py_identity_model.aio.token_validation as aio_tv
from py_identity_model.core.models import TokenValidationConfig
import py_identity_model.core.token_validation_logic as tvl
from py_identity_model.core.token_validation_logic import (
    _enforce_strict_audience,
    build_resolved_config,
    decode_with_config,
)
from py_identity_model.exceptions import (
    CertificateBindingError,
    InvalidAudienceException,
)
import py_identity_model.sync.token_validation as sync_tv


def _offline_cfg(**kw) -> TokenValidationConfig:
    return TokenValidationConfig(
        perform_disco=False, key={"kty": "RSA"}, algorithms=["RS256"], **kw
    )


class TestStrictAudienceLogic:
    def test_extra_audience_rejected(self):
        with pytest.raises(InvalidAudienceException, match="outside the configured"):
            _enforce_strict_audience({"aud": ["my-api", "attacker-api"]}, "my-api")

    def test_all_audiences_allowed_passes(self):
        _enforce_strict_audience({"aud": ["my-api", "other"]}, ["my-api", "other"])

    def test_single_string_audience(self):
        _enforce_strict_audience({"aud": "my-api"}, "my-api")
        with pytest.raises(InvalidAudienceException):
            _enforce_strict_audience({"aud": "wrong-api"}, "my-api")


class TestStrictAudienceChokepoint:
    def test_strict_audience_rejects_extra_at_decode(self, monkeypatch):
        # Patch the underlying decode to return a token with a secondary audience;
        # strict_audience must reject it.
        monkeypatch.setattr(
            tvl, "decode_and_validate_jwt", lambda **_: {"aud": ["my-api", "evil"]}
        )
        cfg = _offline_cfg(audience="my-api", strict_audience=True)
        with pytest.raises(InvalidAudienceException):
            decode_with_config("a.b.c", cfg)

    def test_default_does_not_apply_strict_audience(self, monkeypatch):
        # OPT-IN: with strict_audience=False (default) the same secondary-audience
        # token is accepted (PyJWT's set-intersection behaviour, unchanged).
        monkeypatch.setattr(
            tvl, "decode_and_validate_jwt", lambda **_: {"aud": ["my-api", "evil"]}
        )
        cfg = _offline_cfg(audience="my-api")  # strict_audience defaults False
        assert decode_with_config("a.b.c", cfg) == {"aud": ["my-api", "evil"]}

    def test_build_resolved_config_propagates_strict_audience(self):
        resolved = build_resolved_config(
            _offline_cfg(strict_audience=True), {"kty": "RSA"}, "RS256"
        )
        assert resolved.strict_audience is True


class TestCertBindingWiring:
    def test_cert_provided_enforces_binding(self, monkeypatch):
        # Token lacks cnf; providing a client certificate must trigger RFC 8705
        # binding enforcement (fail closed).
        monkeypatch.setattr(
            sync_tv, "decode_with_config", lambda *_a, **_k: {"sub": "u"}
        )
        with pytest.raises(CertificateBindingError):
            sync_tv.validate_token(
                "a.b.c", _offline_cfg(), client_certificate="dummy-cert"
            )

    def test_no_cert_is_unchanged_bearer(self, monkeypatch):
        # OPT-IN: without a client certificate, binding is never checked — the same
        # unbound token validates (default behaviour).
        monkeypatch.setattr(
            sync_tv, "decode_with_config", lambda *_a, **_k: {"sub": "u"}
        )
        assert sync_tv.validate_token("a.b.c", _offline_cfg()) == {"sub": "u"}

    @pytest.mark.asyncio
    async def test_aio_cert_provided_enforces_binding(self, monkeypatch):
        monkeypatch.setattr(
            aio_tv, "decode_with_config", lambda *_a, **_k: {"sub": "u"}
        )
        with pytest.raises(CertificateBindingError):
            await aio_tv.validate_token(
                "a.b.c", _offline_cfg(), client_certificate="dummy-cert"
            )

    @pytest.mark.asyncio
    async def test_aio_no_cert_is_unchanged_bearer(self, monkeypatch):
        monkeypatch.setattr(
            aio_tv, "decode_with_config", lambda *_a, **_k: {"sub": "u"}
        )
        assert await aio_tv.validate_token("a.b.c", _offline_cfg()) == {"sub": "u"}
