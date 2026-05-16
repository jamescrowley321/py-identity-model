"""
Proves the kid-miss refresh cooldown bounds DoS amplification.

Threat model: an unauthenticated attacker spams JWTs with random unknown
``kid`` values against the token-validation endpoint. Each kid-miss triggers
a forced JWKS refresh from the cache layer. Without a cooldown, the
amplification factor is 1:1 — attacker controls a per-request JWKS fetch
against the upstream OP. At ~100 RPS this trivially trips the upstream's
rate limit and breaks validation for legitimate traffic too.

These tests pin the contract:
- 1 prime + 1 refresh covers an arbitrary number of attacker requests
  inside the cooldown window (regardless of distinct kids used).
- Cooldown does NOT block when the cache has no keys to fall back on.
- Cooldown does NOT block legitimate tokens with cached kids.
- Cooldown expires after its window; rotation propagates within one window.
- The cooldown is per ``jwks_uri`` — an attacker against one OP cannot
  suppress refreshes for a different OP.
"""

import asyncio
import time

import httpx
import pytest
import respx

from py_identity_model.aio.token_validation import (
    _kid_miss_last_attempt as async_kid_miss_last_attempt,
)
from py_identity_model.aio.token_validation import (
    clear_discovery_cache as async_clear_discovery_cache,
)
from py_identity_model.aio.token_validation import (
    clear_jwks_cache as async_clear_jwks_cache,
)
from py_identity_model.aio.token_validation import (
    validate_token as async_validate_token,
)
from py_identity_model.core.jwks_cache import (
    DEFAULT_KID_MISS_REFRESH_COOLDOWN_SECONDS,
    _reset_env_for_testing,
    get_kid_miss_cooldown,
    should_attempt_kid_miss_refresh,
)
from py_identity_model.core.models import TokenValidationConfig
from py_identity_model.exceptions import TokenValidationException
from py_identity_model.sync.token_validation import (
    _kid_miss_last_attempt as sync_kid_miss_last_attempt,
)
from py_identity_model.sync.token_validation import (
    clear_discovery_cache,
    clear_jwks_cache,
    validate_token,
)

from .token_validation_helpers import (
    DISCO_RESPONSE_WITH_JWKS,
    generate_rsa_keypair,
    sign_jwt,
)


DISCO_URL = "https://example.com/.well-known/openid-configuration"
JWKS_URL = "https://example.com/jwks"


@pytest.fixture(autouse=True)
def _clear_caches():
    clear_discovery_cache()
    clear_jwks_cache()
    async_clear_discovery_cache()
    async_clear_jwks_cache()
    _reset_env_for_testing()
    yield
    clear_discovery_cache()
    clear_jwks_cache()
    async_clear_discovery_cache()
    async_clear_jwks_cache()
    _reset_env_for_testing()


def _sign_unknown_kid_token(kid: str) -> str:
    """Forge a JWT header advertising the given kid but sign with a fresh
    keypair the verifier will never see — exercises the kid-miss path."""
    _, pem = generate_rsa_keypair()
    return sign_jwt(
        pem,
        {"sub": "attacker", "iss": "https://example.com"},
        headers={"kid": kid},
    )


# ============================================================================
# Pure-function semantics for the gate. Decouples the contract from the
# sync/async plumbing so a flipped predicate would fail here too.
# ============================================================================


class TestShouldAttemptKidMissRefreshContract:
    def test_proceeds_when_no_prior_attempt(self):
        assert should_attempt_kid_miss_refresh(
            last_attempts={},
            jwks_uri=JWKS_URL,
            has_cached_keys=True,
            now=100.0,
        )

    def test_proceeds_when_no_cached_keys_even_inside_cooldown(self):
        recent = {JWKS_URL: 100.0}
        assert should_attempt_kid_miss_refresh(
            last_attempts=recent,
            jwks_uri=JWKS_URL,
            has_cached_keys=False,
            now=100.5,
        )

    def test_blocks_when_recent_attempt_with_cached_keys(self):
        cooldown = get_kid_miss_cooldown()
        recent = {JWKS_URL: 100.0}
        assert not should_attempt_kid_miss_refresh(
            last_attempts=recent,
            jwks_uri=JWKS_URL,
            has_cached_keys=True,
            now=100.0 + cooldown / 2,
        )

    def test_proceeds_after_cooldown_elapsed(self):
        cooldown = get_kid_miss_cooldown()
        old = {JWKS_URL: 100.0}
        assert should_attempt_kid_miss_refresh(
            last_attempts=old,
            jwks_uri=JWKS_URL,
            has_cached_keys=True,
            now=100.0 + cooldown + 0.01,
        )

    def test_cooldown_is_per_jwks_uri(self):
        """An attacker against OP-A cannot suppress refreshes for OP-B."""
        other_uri = "https://other.example/jwks"
        recent = {JWKS_URL: 100.0}
        assert should_attempt_kid_miss_refresh(
            last_attempts=recent,
            jwks_uri=other_uri,
            has_cached_keys=True,
            now=100.0,
        )


# ============================================================================
# End-to-end: under sustained kid-miss attack, only 1 prime + 1 refresh
# reach the upstream JWKS endpoint, regardless of attacker request volume.
# ============================================================================

ATTACKER_REQUEST_COUNT = 25
EXPECTED_FETCH_COUNT = 2  # 1 prime + 1 refresh inside cooldown window


class TestKidMissCooldownBoundsAmplification:
    @respx.mock
    def test_sync_cooldown_caps_fetches_under_attack(self):
        defender_key_dict, _defender_pem = generate_rsa_keypair()
        defender_key_dict["kid"] = "defender-kid"

        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        jwks_route = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [defender_key_dict]})
        )

        config = TokenValidationConfig(
            perform_disco=True, audience=None, issuer="https://example.com"
        )

        attacker_kids = [f"attacker-kid-{i}" for i in range(ATTACKER_REQUEST_COUNT)]
        tokens = [_sign_unknown_kid_token(kid) for kid in attacker_kids]

        rejections = 0
        for token in tokens:
            try:
                validate_token(
                    jwt=token,
                    token_validation_config=config,
                    disco_doc_address=DISCO_URL,
                )
            except TokenValidationException:
                rejections += 1

        # Every attacker request must fail (no matching kid).
        assert rejections == ATTACKER_REQUEST_COUNT
        # And the upstream JWKS endpoint sees at most 1 prime + 1 refresh,
        # not one fetch per attacker request.
        assert jwks_route.call_count == EXPECTED_FETCH_COUNT

    @pytest.mark.asyncio
    @respx.mock
    async def test_async_cooldown_caps_fetches_under_attack(self):
        defender_key_dict, _defender_pem = generate_rsa_keypair()
        defender_key_dict["kid"] = "defender-kid"

        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        jwks_route = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [defender_key_dict]})
        )

        config = TokenValidationConfig(
            perform_disco=True, audience=None, issuer="https://example.com"
        )

        attacker_kids = [f"attacker-kid-{i}" for i in range(ATTACKER_REQUEST_COUNT)]
        tokens = [_sign_unknown_kid_token(kid) for kid in attacker_kids]

        async def _try(token: str) -> bool:
            try:
                await async_validate_token(
                    jwt=token,
                    token_validation_config=config,
                    disco_doc_address=DISCO_URL,
                )
                return False
            except TokenValidationException:
                return True

        results = await asyncio.gather(*(_try(t) for t in tokens))
        assert all(results)
        assert jwks_route.call_count == EXPECTED_FETCH_COUNT


# ============================================================================
# Cooldown must NOT block legitimate validation: tokens with already-cached
# kids never trigger the cooldown, and a real key rotation propagates within
# one cooldown window.
# ============================================================================


class TestCooldownDoesNotBlockLegitimateTraffic:
    @respx.mock
    def test_cached_kid_does_not_trip_cooldown(self):
        """Validating a token whose kid IS in the cache must not consume
        cooldown budget — kid-miss path never fires."""
        key_dict, pem = generate_rsa_keypair()
        key_dict["kid"] = "cached-kid"

        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        jwks_route = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [key_dict]})
        )

        config = TokenValidationConfig(
            perform_disco=True, audience=None, issuer="https://example.com"
        )

        legitimate_token = sign_jwt(
            pem,
            {"sub": "user1", "iss": "https://example.com"},
            headers={"kid": "cached-kid"},
        )

        for _ in range(10):
            validate_token(
                jwt=legitimate_token,
                token_validation_config=config,
                disco_doc_address=DISCO_URL,
            )

        # Single prime fetch, no refreshes, cooldown dict never populated.
        assert jwks_route.call_count == 1
        assert JWKS_URL not in sync_kid_miss_last_attempt

    @respx.mock
    def test_rotation_propagates_after_cooldown_elapses(self):
        """A real rotation (new key on upstream) must propagate on the very
        next kid-miss after the cooldown window — proving the cooldown is
        bounded, not permanent."""
        old_key_dict, _ = generate_rsa_keypair()
        old_key_dict["kid"] = "old-kid"
        new_key_dict, new_pem = generate_rsa_keypair()
        new_key_dict["kid"] = "new-kid"

        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        # First fetch returns old; second fetch returns new (rotation).
        jwks_route = respx.get(JWKS_URL).mock(
            side_effect=[
                httpx.Response(200, json={"keys": [old_key_dict]}),
                httpx.Response(200, json={"keys": [old_key_dict]}),
                httpx.Response(200, json={"keys": [new_key_dict]}),
            ]
        )

        config = TokenValidationConfig(
            perform_disco=True, audience=None, issuer="https://example.com"
        )

        rotation_token = sign_jwt(
            new_pem,
            {"sub": "user1", "iss": "https://example.com"},
            headers={"kid": "new-kid"},
        )

        # 1st attempt: cache has only old-kid → kid-miss → refresh fires →
        # upstream still serves old-kid → rotation_token can't validate yet.
        with pytest.raises(TokenValidationException):
            validate_token(
                jwt=rotation_token,
                token_validation_config=config,
                disco_doc_address=DISCO_URL,
            )
        assert jwks_route.call_count == 2  # noqa: PLR2004

        # 2nd attempt inside cooldown: refresh suppressed, still fails.
        with pytest.raises(TokenValidationException):
            validate_token(
                jwt=rotation_token,
                token_validation_config=config,
                disco_doc_address=DISCO_URL,
            )
        assert jwks_route.call_count == 2  # noqa: PLR2004

        # Simulate cooldown elapse by backdating the last-attempt timestamp.
        cooldown = get_kid_miss_cooldown()
        sync_kid_miss_last_attempt[JWKS_URL] = time.time() - cooldown - 1.0

        # 3rd attempt past cooldown: refresh fires again, upstream now serves
        # new-kid, rotation_token validates successfully.
        decoded = validate_token(
            jwt=rotation_token,
            token_validation_config=config,
            disco_doc_address=DISCO_URL,
        )
        assert decoded["sub"] == "user1"
        assert jwks_route.call_count == 3  # noqa: PLR2004


# ============================================================================
# Cooldown is per-URI: an attacker hammering OP-A cannot suppress legitimate
# rotation refreshes for OP-B.
# ============================================================================


class TestCooldownIsolationAcrossIssuers:
    @respx.mock
    def test_per_issuer_cooldown_does_not_cross_contaminate(self):
        other_disco_url = "https://other.example/.well-known/openid-configuration"
        other_jwks_url = "https://other.example/jwks"
        other_disco_response = {
            "issuer": "https://other.example",
            "authorization_endpoint": "https://other.example/authorize",
            "token_endpoint": "https://other.example/token",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "jwks_uri": other_jwks_url,
        }

        attacker_key_dict, _ = generate_rsa_keypair()
        attacker_key_dict["kid"] = "attacker-side-kid"
        defender_key_dict, defender_pem = generate_rsa_keypair()
        defender_key_dict["kid"] = "defender-kid"

        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        respx.get(other_disco_url).mock(
            return_value=httpx.Response(200, json=other_disco_response)
        )
        attacker_jwks_route = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [attacker_key_dict]})
        )
        defender_jwks_route = respx.get(other_jwks_url).mock(
            return_value=httpx.Response(200, json={"keys": [defender_key_dict]})
        )

        config_attacker = TokenValidationConfig(
            perform_disco=True, audience=None, issuer="https://example.com"
        )
        config_defender = TokenValidationConfig(
            perform_disco=True, audience=None, issuer="https://other.example"
        )

        # Saturate the attacker-side cooldown.
        for i in range(ATTACKER_REQUEST_COUNT):
            with pytest.raises(TokenValidationException):
                validate_token(
                    jwt=_sign_unknown_kid_token(f"junk-{i}"),
                    token_validation_config=config_attacker,
                    disco_doc_address=DISCO_URL,
                )

        # Defender-side issuer must NOT be in cooldown — legitimate token
        # signed by the defender's key validates without interference.
        defender_token = sign_jwt(
            defender_pem,
            {"sub": "legit", "iss": "https://other.example"},
            headers={"kid": "defender-kid"},
        )
        decoded = validate_token(
            jwt=defender_token,
            token_validation_config=config_defender,
            disco_doc_address=other_disco_url,
        )
        assert decoded["sub"] == "legit"

        # Attacker JWKS saw exactly 1 prime + 1 refresh; defender JWKS saw 1
        # prime (legitimate kid hit cache immediately).
        assert attacker_jwks_route.call_count == EXPECTED_FETCH_COUNT
        assert defender_jwks_route.call_count == 1
        # Cooldown state confirms isolation.
        assert JWKS_URL in sync_kid_miss_last_attempt
        assert other_jwks_url not in sync_kid_miss_last_attempt


# ============================================================================
# Env override sanity: KID_MISS_REFRESH_COOLDOWN takes effect when set
# *before* first access. Pins the contract for operators who want to tune.
# ============================================================================


class TestCooldownEnvOverride:
    def test_env_override_changes_cooldown(self, monkeypatch):
        monkeypatch.setenv("KID_MISS_REFRESH_COOLDOWN", "42.5")
        _reset_env_for_testing()
        assert get_kid_miss_cooldown() == 42.5  # noqa: PLR2004

    def test_default_when_unset(self, monkeypatch):
        monkeypatch.delenv("KID_MISS_REFRESH_COOLDOWN", raising=False)
        _reset_env_for_testing()
        assert get_kid_miss_cooldown() == DEFAULT_KID_MISS_REFRESH_COOLDOWN_SECONDS


# Async cooldown state covered for symmetry — most of the integration
# coverage is via the sync end-to-end test above.
class TestAsyncCooldownStateMirrorsSync:
    @pytest.mark.asyncio
    @respx.mock
    async def test_async_cooldown_dict_populated_on_refresh(self):
        defender_key_dict, _ = generate_rsa_keypair()
        defender_key_dict["kid"] = "defender-kid"

        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [defender_key_dict]})
        )

        config = TokenValidationConfig(
            perform_disco=True, audience=None, issuer="https://example.com"
        )

        with pytest.raises(TokenValidationException):
            await async_validate_token(
                jwt=_sign_unknown_kid_token("unknown"),
                token_validation_config=config,
                disco_doc_address=DISCO_URL,
            )

        assert JWKS_URL in async_kid_miss_last_attempt
