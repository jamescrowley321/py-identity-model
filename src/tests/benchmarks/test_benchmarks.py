"""Performance benchmark tests for py-identity-model.

Run with: make test-benchmark
"""

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


# ============================================================================
# PKCE Benchmarks
# ============================================================================


@pytest.mark.benchmark(group="pkce")
def test_bench_generate_pkce_pair(benchmark):
    benchmark(generate_pkce_pair)


@pytest.mark.benchmark(group="pkce")
def test_bench_generate_code_verifier(benchmark):
    benchmark(generate_code_verifier)


@pytest.mark.benchmark(group="pkce")
def test_bench_generate_code_challenge(benchmark):
    verifier = generate_code_verifier()
    benchmark(generate_code_challenge, verifier)


# ============================================================================
# DPoP Benchmarks
# ============================================================================


@pytest.mark.benchmark(group="dpop")
def test_bench_generate_dpop_key_ec(benchmark):
    benchmark(generate_dpop_key, "ES256")


@pytest.mark.benchmark(group="dpop")
def test_bench_generate_dpop_key_rsa(benchmark):
    benchmark(generate_dpop_key, "RS256")


@pytest.mark.benchmark(group="dpop")
def test_bench_create_dpop_proof(benchmark):
    key = generate_dpop_key()
    benchmark(create_dpop_proof, key, "POST", "https://auth.example.com/token")


# ============================================================================
# JAR Benchmarks
# ============================================================================


@pytest.mark.benchmark(group="jar")
def test_bench_create_request_object_ec(benchmark, ec_private_pem):
    benchmark(
        create_request_object,
        private_key=ec_private_pem,
        algorithm="ES256",
        client_id="bench-app",
        audience="https://auth.example.com",
        redirect_uri="https://app.example.com/cb",
    )


@pytest.mark.benchmark(group="jar")
def test_bench_create_request_object_rsa(benchmark, rsa_private_pem):
    benchmark(
        create_request_object,
        private_key=rsa_private_pem,
        algorithm="RS256",
        client_id="bench-app",
        audience="https://auth.example.com",
        redirect_uri="https://app.example.com/cb",
    )


# ============================================================================
# FAPI Validation Benchmarks
# ============================================================================


@pytest.mark.benchmark(group="fapi")
def test_bench_validate_fapi_request(benchmark):
    benchmark(
        validate_fapi_authorization_request,
        response_type="code",
        code_challenge="challenge_value",
        code_challenge_method="S256",
        redirect_uri="https://app.example.com/cb",
        use_par=True,
        algorithm="ES256",
    )


@pytest.mark.benchmark(group="fapi")
def test_bench_validate_fapi_client(benchmark):
    benchmark(
        validate_fapi_client_config,
        has_client_authentication=True,
        use_dpop=True,
    )


# ============================================================================
# Discovery Policy Benchmarks
# ============================================================================


@pytest.mark.benchmark(group="discovery")
def test_bench_parse_discovery_url(benchmark):
    benchmark(parse_discovery_url, "https://auth.example.com")


@pytest.mark.benchmark(group="discovery")
def test_bench_validate_url_scheme(benchmark):
    policy = DiscoveryPolicy()
    benchmark(validate_url_scheme, "https://auth.example.com/token", policy)


# ============================================================================
# JWK Parsing Benchmarks
# ============================================================================


@pytest.mark.benchmark(group="jwk")
def test_bench_jwks_from_dict(benchmark, sample_jwk_dict):
    benchmark(jwks_from_dict, sample_jwk_dict)


# ============================================================================
# Identity / Claims Benchmarks
# ============================================================================


@pytest.mark.benchmark(group="identity")
def test_bench_to_principal(benchmark, sample_claims):
    benchmark(to_principal, sample_claims)


# ============================================================================
# JWT Decode Benchmarks (core validation operation)
# ============================================================================


@pytest.mark.benchmark(group="jwt")
def test_bench_jwt_decode(benchmark, sample_signed_jwt, ec_public_pem):
    """Benchmark raw JWT decode + verification (the core validation path)."""
    import jwt as pyjwt

    def decode_jwt():
        return pyjwt.decode(
            sample_signed_jwt,
            ec_public_pem,
            algorithms=["ES256"],
            audience="bench-api",
        )

    benchmark(decode_jwt)
