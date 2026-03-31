"""Performance benchmark tests for py-identity-model.

Run with: make test-benchmark
"""

import jwt as pyjwt
import pytest

from py_identity_model import (
    validate_fapi_authorization_request,
    validate_fapi_client_config,
)
from py_identity_model.core.discovery_policy import (
    DiscoveryPolicy,
    parse_discovery_url,
    validate_url_scheme,
)
from py_identity_model.core.dpop import (
    create_dpop_proof,
    generate_dpop_key,
)
from py_identity_model.core.jar import create_request_object
from py_identity_model.core.parsers import jwks_from_dict
from py_identity_model.core.pkce import (
    generate_code_challenge,
    generate_code_verifier,
    generate_pkce_pair,
)
from py_identity_model.identity import to_principal


# Test constants
PKCE_PAIR_LENGTH = 2

# ============================================================================
# PKCE Benchmarks
# ============================================================================


@pytest.mark.benchmark(group="pkce")
def test_bench_generate_pkce_pair(benchmark):
    result = benchmark(generate_pkce_pair)
    assert result is not None
    assert len(result) == PKCE_PAIR_LENGTH


@pytest.mark.benchmark(group="pkce")
def test_bench_generate_code_verifier(benchmark):
    result = benchmark(generate_code_verifier)
    assert isinstance(result, str)


@pytest.mark.benchmark(group="pkce")
def test_bench_generate_code_challenge(benchmark):
    verifier = generate_code_verifier()
    result = benchmark(generate_code_challenge, verifier)
    assert isinstance(result, str)


# ============================================================================
# DPoP Benchmarks
# ============================================================================


@pytest.mark.benchmark(group="dpop")
def test_bench_generate_dpop_key_ec(benchmark):
    result = benchmark(generate_dpop_key, "ES256")
    assert result is not None


@pytest.mark.benchmark(group="dpop")
def test_bench_generate_dpop_key_rsa(benchmark):
    result = benchmark(generate_dpop_key, "RS256")
    assert result is not None


@pytest.mark.benchmark(group="dpop")
def test_bench_create_dpop_proof(benchmark):
    key = generate_dpop_key()
    result = benchmark(create_dpop_proof, key, "POST", "https://auth.example.com/token")
    assert isinstance(result, str)


# ============================================================================
# JAR Benchmarks
# ============================================================================


@pytest.mark.benchmark(group="jar")
def test_bench_create_request_object_ec(benchmark, ec_private_pem):
    result = benchmark(
        create_request_object,
        private_key=ec_private_pem,
        algorithm="ES256",
        client_id="bench-app",
        audience="https://auth.example.com",
        redirect_uri="https://app.example.com/cb",
    )
    assert isinstance(result, str)


@pytest.mark.benchmark(group="jar")
def test_bench_create_request_object_rsa(benchmark, rsa_private_pem):
    result = benchmark(
        create_request_object,
        private_key=rsa_private_pem,
        algorithm="RS256",
        client_id="bench-app",
        audience="https://auth.example.com",
        redirect_uri="https://app.example.com/cb",
    )
    assert isinstance(result, str)


# ============================================================================
# FAPI Validation Benchmarks
# ============================================================================


@pytest.mark.benchmark(group="fapi")
def test_bench_validate_fapi_request(benchmark):
    result = benchmark(
        validate_fapi_authorization_request,
        response_type="code",
        code_challenge="challenge_value",
        code_challenge_method="S256",
        redirect_uri="https://app.example.com/cb",
        use_par=True,
        algorithm="ES256",
    )
    assert result is not None


@pytest.mark.benchmark(group="fapi")
def test_bench_validate_fapi_client(benchmark):
    result = benchmark(
        validate_fapi_client_config,
        auth_method="private_key_jwt",
        use_dpop=True,
    )
    assert result is not None


# ============================================================================
# Discovery Policy Benchmarks
# ============================================================================


@pytest.mark.benchmark(group="discovery")
def test_bench_parse_discovery_url(benchmark):
    result = benchmark(parse_discovery_url, "https://auth.example.com")
    assert result is not None


@pytest.mark.benchmark(group="discovery")
def test_bench_validate_url_scheme(benchmark):
    policy = DiscoveryPolicy()
    benchmark(validate_url_scheme, "https://auth.example.com/token", policy)
    # validate_url_scheme returns None on success (raises on failure)


# ============================================================================
# JWK Parsing Benchmarks
# ============================================================================


@pytest.mark.benchmark(group="jwk")
def test_bench_jwks_from_dict(benchmark, sample_jwk_dict):
    result = benchmark(jwks_from_dict, sample_jwk_dict)
    assert result is not None


# ============================================================================
# Identity / Claims Benchmarks
# ============================================================================


@pytest.mark.benchmark(group="identity")
def test_bench_to_principal(benchmark, sample_claims):
    result = benchmark(to_principal, sample_claims)
    assert result is not None


# ============================================================================
# JWT Decode Benchmarks (core validation operation)
# ============================================================================


@pytest.mark.benchmark(group="jwt")
def test_bench_pyjwt_decode_baseline(benchmark, sample_signed_jwt, ec_public_pem):
    """Benchmark raw pyjwt.decode() as a baseline for comparison (not py-identity-model code)."""

    def decode_jwt():
        return pyjwt.decode(
            sample_signed_jwt,
            ec_public_pem,
            algorithms=["ES256"],
            audience="bench-api",
        )

    result = benchmark(decode_jwt)
    assert result is not None
