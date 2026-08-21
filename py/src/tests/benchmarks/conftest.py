"""Fixtures for performance benchmark tests."""

import time
from types import MappingProxyType

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
import jwt as pyjwt
import pytest


@pytest.fixture(scope="session")
def ec_private_key():
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture(scope="session")
def ec_private_pem(ec_private_key):
    return ec_private_key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    )


@pytest.fixture(scope="session")
def ec_public_pem(ec_private_key):
    return ec_private_key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )


@pytest.fixture(scope="session")
def rsa_private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def rsa_private_pem(rsa_private_key):
    return rsa_private_key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    )


@pytest.fixture(scope="session")
def rsa_public_pem(rsa_private_key):
    return rsa_private_key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )


@pytest.fixture(scope="session")
def sample_jwk_dict():
    """A sample RSA JWK dict for parsing benchmarks."""
    return {
        "kty": "RSA",
        "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        "e": "AQAB",
        "alg": "RS256",
        "kid": "bench-key-1",
        "use": "sig",
    }


@pytest.fixture(scope="session")
def sample_signed_jwt(ec_private_pem):
    """A sample signed JWT for validation benchmarks."""
    now = int(time.time())
    claims = {
        "iss": "https://bench.example.com",
        "sub": "user123",
        "aud": "bench-api",
        "exp": now + 86400,
        "iat": now,
        "nbf": now,
    }
    return pyjwt.encode(claims, ec_private_pem, algorithm="ES256")


@pytest.fixture(scope="session")
def sample_claims():
    """Sample claims dict for identity benchmarks (frozen to prevent mutation)."""
    return MappingProxyType(
        {
            "sub": "user123",
            "name": "Bench User",
            "email": "bench@example.com",
            "roles": ["admin", "user"],
            "iss": "https://bench.example.com",
            "aud": "bench-api",
        }
    )
