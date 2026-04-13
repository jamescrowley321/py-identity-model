"""Tests for cache isolation -- ensures no cross-user token pollution."""

import base64
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt as pyjwt
import pytest

from py_identity_model.core.jwt_helpers import decode_and_validate_jwt


@pytest.fixture
def rsa_key_pair():
    """Generate an RSA key pair for testing."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # Get public key as JWK-style dict
    public_numbers = public_key.public_numbers()

    def _int_to_base64url(n, length=None):
        b = n.to_bytes((n.bit_length() + 7) // 8, byteorder="big")
        if length and len(b) < length:
            b = b"\x00" * (length - len(b)) + b
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

    key_dict = {
        "kty": "RSA",
        "n": _int_to_base64url(public_numbers.n),
        "e": _int_to_base64url(public_numbers.e),
        "kid": "test-key-1",
    }

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return pem, key_dict


def _make_token(
    private_key, sub: str, aud: str = "test-aud", iss: str = "test-iss"
) -> str:
    """Create a signed JWT with the given sub claim."""
    now = time.time()
    payload = {
        "sub": sub,
        "aud": aud,
        "iss": iss,
        "iat": int(now),
        "exp": int(now) + 3600,
    }
    return pyjwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers={"kid": "test-key-1"},
    )


class TestCrossUserCacheIsolation:
    """Verify that tokens for different users never return wrong claims."""

    def test_50_distinct_subs_return_correct_claims(self, rsa_key_pair):
        """Generate tokens for 50 distinct subjects and validate each returns correct sub."""
        pem, key_dict = rsa_key_pair

        # Generate 50 tokens with unique subs
        subs = [f"user-{i:03d}@example.com" for i in range(50)]
        tokens = [(sub, _make_token(pem, sub)) for sub in subs]

        # Validate each token and assert correct sub is returned
        for expected_sub, token in tokens:
            result = decode_and_validate_jwt(
                jwt=token,
                key=key_dict,
                algorithms=["RS256"],
                audience="test-aud",
                issuer="test-iss",
                options=None,
            )
            assert result["sub"] == expected_sub, (
                f"Expected sub={expected_sub!r} but got sub={result['sub']!r}"
            )

    def test_same_sub_different_claims_not_confused(self, rsa_key_pair):
        """Tokens with same sub but different iat should return distinct results."""
        pem, key_dict = rsa_key_pair

        now = int(time.time()) - 100  # 100s in the past to avoid iat race
        tokens = []
        for i in range(10):
            payload = {
                "sub": "same-user",
                "aud": "test-aud",
                "iss": "test-iss",
                "iat": now
                - i,  # Different iat makes each token unique (all in the past)
                "exp": int(time.time()) + 3600,
                "request_id": f"req-{i}",
            }
            token = pyjwt.encode(
                payload, pem, algorithm="RS256", headers={"kid": "test-key-1"}
            )
            tokens.append((i, token))

        for i, token in tokens:
            result = decode_and_validate_jwt(
                jwt=token,
                key=key_dict,
                algorithms=["RS256"],
                audience="test-aud",
                issuer="test-iss",
                options=None,
            )
            assert result["request_id"] == f"req-{i}"
