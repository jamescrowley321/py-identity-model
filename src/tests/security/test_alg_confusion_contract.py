"""Adversarial exception-contract tests for the alg-consistency guard (F-01).

``_ALG_TO_KTY`` (``core/parsers.py``) maps only asymmetric algorithms, so
``_validate_key_alg_consistency`` NO-OPS for exactly the algorithms an
alg-confusion attacker chooses — ``HS256``/``HS384``/``HS512`` and ``none`` —
whenever the JWK omits its optional ``alg`` member (spec-legal per RFC 7517).

Reachability (default discovery path, no-kid token, single alg-less RSA JWKS
key):

    validate_token -> extract_jwt_header_fields (unverified alg)
      -> find_key_by_kid(None, [RSA, alg=None], "HS256")   # guard no-ops
      -> decode_and_validate_jwt(..., algorithms=["HS256"])
        -> PyJWK(rsa_key, "HS256")  # raises jwt.InvalidKeyError  (or, for
                                    # alg=none, NotImplementedError)

Neither ``InvalidKeyError`` nor ``NotImplementedError`` is caught by
``decode_and_validate_jwt``'s except chain, so an UNTYPED exception escapes the
documented "only ``PyIdentityModelException``" contract -> unhandled 500 /
traceback leak. This is the #488-490 alg-guard gap.

Not a forgery (PyJWT's own ``kty``/``from_jwk`` checks block that) — the defect
is the broken exception contract. These tests assert a typed
``PyIdentityModelException``/``TokenValidationException`` and XFAIL until the
guard rejects HS*/none and the decoder wraps the stray exception.
"""

import httpx
import jwt as pyjwt
import pytest
import respx

from py_identity_model.core.models import TokenValidationConfig
from py_identity_model.core.parsers import find_key_by_kid, jwks_from_dict
from py_identity_model.exceptions import (
    PyIdentityModelException,
    TokenValidationException,
)
from py_identity_model.sync.token_validation import (
    clear_discovery_cache,
    clear_jwks_cache,
    validate_token,
)

from ._security_helpers import generate_rsa_keypair, unsigned_none_alg_jwt


pytestmark = pytest.mark.unit

DISCO_URL = "https://example.com/.well-known/openid-configuration"
_DISCO_DOC = {
    "issuer": "https://example.com",
    "jwks_uri": "https://example.com/jwks",
    "authorization_endpoint": "https://example.com/authorize",
    "token_endpoint": "https://example.com/token",
    "response_types_supported": ["code"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"],
}


@pytest.fixture(autouse=True)
def _clear_caches():
    clear_discovery_cache()
    clear_jwks_cache()
    yield
    clear_discovery_cache()
    clear_jwks_cache()


def _alg_less_rsa_jwk() -> dict:
    """A spec-legal RSA JWK with the optional ``alg`` member omitted."""
    key_dict, _ = generate_rsa_keypair()
    key_dict.pop("alg", None)
    key_dict.pop("kid", None)
    return key_dict


@pytest.mark.parametrize("attacker_alg", ["HS256", "none"])
@pytest.mark.xfail(
    strict=True,
    reason="F-01: _validate_key_alg_consistency no-ops for HS*/none, so a "
    "no-kid symmetric/none alg against a single alg-less RSA JWK is not rejected",
)
def test_find_key_by_kid_rejects_symmetric_alg_against_rsa_key(
    attacker_alg: str,
) -> None:
    key = jwks_from_dict(_alg_less_rsa_jwk())
    # No kid + a single signing key routes through the no-kid branch, where the
    # guard must reject an HS*/none alg paired with an RSA key.
    with pytest.raises(TokenValidationException):
        find_key_by_kid(None, [key], jwt_alg=attacker_alg)


@pytest.mark.xfail(
    strict=True,
    reason="F-01: HS256 no-kid token vs single alg-less RSA JWK escapes as an "
    "untyped jwt.InvalidKeyError, violating the PyIdentityModelException contract",
)
@respx.mock
def test_validate_token_hs256_no_kid_raises_typed_exception() -> None:
    jwk = _alg_less_rsa_jwk()
    # >= 32 bytes so PyJWT does not raise InsecureKeyLengthWarning on encode;
    # the value is irrelevant — PyJWK(rsa_key, "HS256") fails before any verify.
    token = pyjwt.encode(
        {"sub": "attacker", "iss": "https://example.com"},
        "attacker-shared-secret-padding-0123456789",
        algorithm="HS256",
    )
    respx.get(DISCO_URL).mock(return_value=httpx.Response(200, json=_DISCO_DOC))
    respx.get("https://example.com/jwks").mock(
        return_value=httpx.Response(200, json={"keys": [jwk]})
    )
    config = TokenValidationConfig(perform_disco=True, audience=None)
    with pytest.raises(PyIdentityModelException):
        validate_token(
            jwt=token,
            token_validation_config=config,
            disco_doc_address=DISCO_URL,
        )


@pytest.mark.xfail(
    strict=True,
    reason="F-01: alg=none no-kid token vs single alg-less RSA JWK escapes as an "
    "untyped NotImplementedError, violating the PyIdentityModelException contract",
)
@respx.mock
def test_validate_token_none_alg_no_kid_raises_typed_exception() -> None:
    jwk = _alg_less_rsa_jwk()
    token = unsigned_none_alg_jwt({"sub": "attacker", "iss": "https://example.com"})
    respx.get(DISCO_URL).mock(return_value=httpx.Response(200, json=_DISCO_DOC))
    respx.get("https://example.com/jwks").mock(
        return_value=httpx.Response(200, json={"keys": [jwk]})
    )
    config = TokenValidationConfig(perform_disco=True, audience=None)
    with pytest.raises(PyIdentityModelException):
        validate_token(
            jwt=token,
            token_validation_config=config,
            disco_doc_address=DISCO_URL,
        )
