"""Adversarial fail-closed tests for discovery-endpoint SSRF (F-05, F-06).

The discovery parser authority/scheme-validates seven endpoint fields
(``response_processors.py`` ``_endpoint_names``) but omits two endpoint-bearing
fields:

* ``mtls_endpoint_aliases`` (F-05) — routes mTLS-authenticated token/PAR/etc.
  requests, and is copied into ``DiscoveryDocumentResponse`` verbatim, so a
  malicious/compromised OP can redirect a cert-bearing request to a link-local
  metadata host over plaintext HTTP (SSRF + HTTPS->HTTP downgrade).
* ``pushed_authorization_request_endpoint`` (F-06) — a compromised OP can make
  the client POST ``client_id``/``redirect_uri``/PKCE ``code_challenge``/
  ``client_secret`` to an attacker or plaintext host (credential-exfil SSRF).

``pushed_authorization_request_endpoint`` (F-06) now joins the authority/scheme
validation loop (``_endpoint_names``), so a discovery document advertising a
foreign-authority / plaintext URL there is REJECTED (``is_successful=False`` —
``DiscoveryException`` collapsed by ``handle_discovery_error``).

``mtls_endpoint_aliases`` (F-05) cannot be issuer-authority-matched, because
RFC 8705 §5 mTLS endpoints legitimately live on a separate host (e.g.
``mtls.example.com`` under issuer ``example.com`` — see
``test_mtls.py::TestDiscoveryParsesMtlsFields``). Instead each alias URL is
scheme-validated (no HTTPS->HTTP downgrade) and rejected if its host is an
internal/reserved IP literal (link-local metadata / RFC1918 / loopback SSRF);
a legitimate cross-host *hostname* alias is still accepted. Hostname-based SSRF
(DNS rebinding) is out of scope (tracked as T9).

``TestSiblingFieldIsValidated`` is a passing control (NOT xfail): it feeds the
identical malicious URL to a *guarded* sibling field (``token_endpoint``) and
proves it is rejected today — pinning the asymmetry the two findings describe.
"""

import httpx
import pytest
import respx

from py_identity_model import (
    DiscoveryDocumentRequest,
    DiscoveryDocumentResponse,
    get_discovery_document,
)


pytestmark = pytest.mark.unit

DISCO_URL = "https://as.example.com/.well-known/openid-configuration"

# The classic link-local metadata SSRF target, plaintext HTTP.
METADATA_HTTP = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
# A foreign-authority but HTTPS URL — bypasses a naive "https only" check and
# must still be rejected on an authority mismatch against the issuer.
FOREIGN_HTTPS = "https://attacker.evil.example/token"
# Internal IP literals reached over HTTPS — pass a naive "https only" check but
# must be rejected as SSRF targets (link-local cloud metadata, RFC1918).
METADATA_HTTPS = "https://169.254.169.254/token"
PRIVATE_HTTPS = "https://10.0.0.5/token"
# A legitimate cross-host mTLS endpoint (RFC 8705 §5) on a separate hostname —
# must be ALLOWED (mTLS aliases are not authority-matched to the issuer).
LEGIT_MTLS_HOST = "https://mtls.as.example.com/token"

_BASE_DISCO = {
    "issuer": "https://as.example.com",
    "jwks_uri": "https://as.example.com/jwks",
    "authorization_endpoint": "https://as.example.com/authorize",
    "token_endpoint": "https://as.example.com/token",
    "response_types_supported": ["code"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"],
}


def _fetch(doc: dict) -> DiscoveryDocumentResponse:
    respx.get(DISCO_URL).mock(return_value=httpx.Response(200, json=doc))
    return get_discovery_document(DiscoveryDocumentRequest(address=DISCO_URL))


@pytest.mark.parametrize(
    "malicious_url", [METADATA_HTTP, METADATA_HTTPS, PRIVATE_HTTPS]
)
@respx.mock
def test_mtls_endpoint_alias_internal_target_is_rejected(malicious_url: str) -> None:
    """F-05: an mTLS alias pointing at a plaintext or internal-IP host fails
    closed — a poisoned discovery document could otherwise route the
    cert-bearing mTLS request to link-local cloud metadata / an RFC1918 host.

    mTLS aliases can't be issuer-authority-matched (RFC 8705 §5 hosts them on a
    separate hostname), so the guard is scheme (no HTTP downgrade) + an
    internal-IP-literal block. Legit foreign *hostname* aliases are covered by
    ``test_mtls_endpoint_alias_cross_host_is_allowed``.
    """
    doc = {**_BASE_DISCO, "mtls_endpoint_aliases": {"token_endpoint": malicious_url}}
    result = _fetch(doc)
    assert result.is_successful is False


@respx.mock
def test_mtls_endpoint_alias_cross_host_is_allowed() -> None:
    """RFC 8705 §5: a legitimate mTLS endpoint on a separate hostname must be
    ACCEPTED (mTLS aliases are not authority-matched to the issuer) — guards
    against an over-strict F-05 fix that would break real cross-host mTLS."""
    doc = {**_BASE_DISCO, "mtls_endpoint_aliases": {"token_endpoint": LEGIT_MTLS_HOST}}
    result = _fetch(doc)
    assert result.is_successful is True


@pytest.mark.parametrize("malicious_url", [METADATA_HTTP, FOREIGN_HTTPS])
@respx.mock
def test_par_endpoint_ssrf_is_rejected(malicious_url: str) -> None:
    doc = {**_BASE_DISCO, "pushed_authorization_request_endpoint": malicious_url}
    result = _fetch(doc)
    assert result.is_successful is False


class TestSiblingFieldIsValidated:
    """Control (passes today): a guarded sibling field rejects the same URLs.

    Proves the asymmetry — the identical malicious URL that F-05/F-06 accept in
    an unguarded field is already rejected in ``token_endpoint``.
    """

    @respx.mock
    def test_foreign_authority_https_token_endpoint_is_rejected(self) -> None:
        doc = {**_BASE_DISCO, "token_endpoint": FOREIGN_HTTPS}
        result = _fetch(doc)
        assert result.is_successful is False

    @respx.mock
    def test_plaintext_metadata_token_endpoint_is_rejected(self) -> None:
        doc = {**_BASE_DISCO, "token_endpoint": METADATA_HTTP}
        result = _fetch(doc)
        assert result.is_successful is False
