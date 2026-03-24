"""Unit tests for PKCE utilities (RFC 7636)."""

from base64 import urlsafe_b64encode
import hashlib
import re

import pytest

from py_identity_model.core.pkce import (
    generate_code_challenge,
    generate_code_verifier,
    generate_pkce_pair,
)


URLSAFE_RE = re.compile(r"^[A-Za-z0-9_-]+$")


@pytest.mark.unit
class TestGenerateCodeVerifier:
    def test_default_length(self):
        v = generate_code_verifier()
        assert len(v) == 128

    def test_custom_length(self):
        v = generate_code_verifier(43)
        assert len(v) == 43

    def test_min_length(self):
        v = generate_code_verifier(43)
        assert len(v) >= 43

    def test_max_length(self):
        v = generate_code_verifier(128)
        assert len(v) <= 128

    def test_too_short_raises(self):
        with pytest.raises(ValueError, match="42"):
            generate_code_verifier(42)

    def test_too_long_raises(self):
        with pytest.raises(ValueError, match="129"):
            generate_code_verifier(129)

    def test_url_safe_characters(self):
        v = generate_code_verifier()
        assert URLSAFE_RE.match(v)

    def test_unique(self):
        v1 = generate_code_verifier()
        v2 = generate_code_verifier()
        assert v1 != v2


@pytest.mark.unit
class TestGenerateCodeChallenge:
    def test_s256_method(self):
        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        # RFC 7636 Appendix B test vector
        expected = (
            urlsafe_b64encode(
                hashlib.sha256(verifier.encode("ascii")).digest()
            )
            .rstrip(b"=")
            .decode("ascii")
        )

        challenge = generate_code_challenge(verifier, "S256")
        assert challenge == expected

    def test_plain_method(self):
        verifier = "some_verifier_string"
        assert generate_code_challenge(verifier, "plain") == verifier

    def test_unsupported_method_raises(self):
        with pytest.raises(ValueError, match="Unsupported"):
            generate_code_challenge("verifier", "SHA512")

    def test_default_method_is_s256(self):
        v = generate_code_verifier()
        c_default = generate_code_challenge(v)
        c_explicit = generate_code_challenge(v, "S256")
        assert c_default == c_explicit


@pytest.mark.unit
class TestGeneratePkcePair:
    def test_returns_tuple(self):
        verifier, challenge = generate_pkce_pair()
        assert isinstance(verifier, str)
        assert isinstance(challenge, str)

    def test_challenge_matches_verifier(self):
        verifier, challenge = generate_pkce_pair("S256")
        assert challenge == generate_code_challenge(verifier, "S256")

    def test_plain_pair(self):
        verifier, challenge = generate_pkce_pair("plain")
        assert verifier == challenge

    def test_custom_length(self):
        verifier, _ = generate_pkce_pair(verifier_length=64)
        assert len(verifier) == 64
