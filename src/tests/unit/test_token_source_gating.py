"""Unit tests for TokenSource capability/credential gating (TH-1.1, #463).

The gating mirrors ``provider_matrix.detect_capabilities``: an unsupported
grant raises :class:`HarnessCapabilityError`, a supported grant with absent
credentials raises :class:`HarnessCredentialError`, and the ``MOCK`` provider
is always mintable (valid + forged).
"""

from __future__ import annotations

import pytest

from ..harness import (
    Grant,
    HarnessCapabilityError,
    HarnessCredentialError,
    Malform,
    MintSpec,
    Provider,
    ProviderConfig,
    TokenSource,
    prime_pool,
)


JWT_SEGMENT_COUNT = 2
DEDUPED_POOL_SIZE = 2


def test_mock_provider_is_always_mintable() -> None:
    source = TokenSource.with_mock()
    token = source.mint(Provider.MOCK, Grant.CLIENT_CREDENTIALS)
    assert token.provider is Provider.MOCK
    assert token.malform is Malform.VALID
    assert token.access_token.count(".") == JWT_SEGMENT_COUNT  # a real JWT
    assert token.expires_at is not None
    assert token.alg == "RS256"


def test_mock_provider_mints_every_forged_class() -> None:
    source = TokenSource.with_mock()
    for malform in Malform:
        token = source.mint(Provider.MOCK, malform=malform)
        assert token.malform is malform
        assert token.access_token  # non-empty


def test_forged_tokens_are_mock_only() -> None:
    node = ProviderConfig(
        provider=Provider.NODE_OIDC,
        capabilities={"client_credentials"},
        token_endpoint="https://issuer.example/token",
        client_id="cid",
        client_secret="secret",
    )
    source = TokenSource([node])
    with pytest.raises(HarnessCapabilityError, match="MOCK provider"):
        source.mint(Provider.NODE_OIDC, malform=Malform.ALG_NONE)


def test_capability_gating_rejects_unsupported_grant() -> None:
    # Advertises only client_credentials — auth_code must be capability-gated.
    node = ProviderConfig(
        provider=Provider.NODE_OIDC,
        capabilities={"client_credentials"},
        token_endpoint="https://issuer.example/token",
        client_id="cid",
        client_secret="secret",
    )
    source = TokenSource([node])
    with pytest.raises(HarnessCapabilityError, match="authorization_code"):
        source.mint(Provider.NODE_OIDC, Grant.AUTHORIZATION_CODE)


def test_credential_gating_when_secret_absent() -> None:
    # Capability present, credentials missing -> credential error (drives skip).
    ory = ProviderConfig(
        provider=Provider.ORY,
        capabilities={"client_credentials"},
        token_endpoint="https://issuer.example/token",
        client_id=None,
        client_secret=None,
    )
    source = TokenSource([ory])
    with pytest.raises(HarnessCredentialError):
        source.mint(Provider.ORY, Grant.CLIENT_CREDENTIALS)


def test_auth_code_requires_injected_minter() -> None:
    keycloak = ProviderConfig(
        provider=Provider.KEYCLOAK,
        capabilities={"authorization_code"},
    )
    source = TokenSource([keycloak])
    with pytest.raises(HarnessCredentialError, match="auth-code minter"):
        source.mint(Provider.KEYCLOAK, Grant.AUTHORIZATION_CODE)


def test_unconfigured_provider_raises_capability_error() -> None:
    source = TokenSource.with_mock()
    with pytest.raises(HarnessCapabilityError, match="not configured"):
        source.mint(Provider.DESCOPE, Grant.CLIENT_CREDENTIALS)


def test_from_discovery_derives_capabilities() -> None:
    disco = {
        "issuer": "http://localhost:9000",
        "token_endpoint": "http://localhost:9000/token",
        "authorization_endpoint": "http://localhost:9000/auth",
        "grant_types_supported": ["client_credentials", "authorization_code"],
    }
    cfg = ProviderConfig.from_discovery(
        Provider.NODE_OIDC, disco, client_id="cid", client_secret="secret"
    )
    assert "client_credentials" in cfg.capabilities
    assert "authorization_code" in cfg.capabilities
    assert cfg.token_endpoint == "http://localhost:9000/token"


def test_auth_code_minter_is_invoked() -> None:
    calls: list[tuple[str | None, str | None]] = []

    def minter(tenant: str | None, scopes: str | None) -> dict:
        calls.append((tenant, scopes))
        return {"access_token": "opaque-token", "token_type": "Bearer"}

    cfg = ProviderConfig(
        provider=Provider.KEYCLOAK,
        capabilities={"authorization_code"},
        auth_code_minter=minter,
    )
    source = TokenSource([cfg])
    token = source.mint(
        Provider.KEYCLOAK, Grant.AUTHORIZATION_CODE, tenant="t1", scopes="openid"
    )
    assert token.access_token == "opaque-token"
    assert calls == [("t1", "openid")]


def test_replay_pool_mints_once() -> None:
    source = TokenSource.with_mock()
    specs = [
        MintSpec(Provider.MOCK, Grant.CLIENT_CREDENTIALS),
        MintSpec(Provider.MOCK, Grant.CLIENT_CREDENTIALS),  # duplicate -> deduped
        MintSpec(Provider.MOCK, malform=Malform.EXPIRED),
    ]
    pool = prime_pool(source, specs)
    assert len(pool) == DEDUPED_POOL_SIZE
    valid = pool.get(MintSpec(Provider.MOCK, Grant.CLIENT_CREDENTIALS))
    assert valid.malform is Malform.VALID
