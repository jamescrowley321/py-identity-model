"""
FAPI 2.0 Security Profile compliance validation.

Provides validation helpers to check that OAuth 2.0 / OpenID Connect
configurations meet FAPI 2.0 Security Profile requirements.

FAPI 2.0 mandates:
- PAR (Pushed Authorization Requests, RFC 9126)
- PKCE with S256 (plain not allowed)
- Authorization code flow only (response_type "code")
- Sender-constrained tokens (DPoP or mTLS)
- Confidential clients
- Strong signing algorithms (PS256, ES256 - not RS256)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import urlparse


if TYPE_CHECKING:
    from .models import DiscoveryDocumentResponse


FAPI2_ALLOWED_SIGNING_ALGORITHMS = frozenset({"PS256", "ES256"})
FAPI2_REQUIRED_PKCE_METHOD = "S256"
FAPI2_REQUIRED_RESPONSE_TYPE = "code"


@dataclass
class FAPIValidationResult:
    """Result of a FAPI 2.0 compliance check.

    Attributes:
        is_compliant: Whether the configuration meets FAPI 2.0 requirements.
        violations: List of specific requirement violations found.
    """

    is_compliant: bool
    violations: list[str] = field(default_factory=list)


def validate_fapi_authorization_request(
    *,
    response_type: str,
    code_challenge: str | None,
    code_challenge_method: str | None,
    redirect_uri: str,
    use_par: bool,
    algorithm: str | None = None,
) -> FAPIValidationResult:
    """Validate an authorization request against FAPI 2.0 requirements.

    All parameters are keyword-only to prevent positional argument mistakes.

    Args:
        response_type: OAuth 2.0 response type.
        code_challenge: PKCE code challenge value.
        code_challenge_method: PKCE method (must be ``"S256"``).
        redirect_uri: The redirect URI (must use ``https``).
        use_par: Whether PAR is being used.
        algorithm: Signing algorithm for JAR/DPoP (validated if provided).

    Returns:
        FAPIValidationResult with compliance status and any violations.
    """
    violations: list[str] = []

    if response_type != FAPI2_REQUIRED_RESPONSE_TYPE:
        violations.append(
            f"response_type must be 'code', got '{response_type}'"
        )

    if not code_challenge:
        violations.append("PKCE code_challenge is required")

    if code_challenge_method is None:
        violations.append("PKCE code_challenge_method is required")
    elif code_challenge_method != FAPI2_REQUIRED_PKCE_METHOD:
        violations.append(
            f"PKCE method must be 'S256', got '{code_challenge_method}'"
        )

    if not use_par:
        violations.append("PAR (Pushed Authorization Requests) is required")

    parsed_uri = urlparse(redirect_uri)
    if parsed_uri.scheme.lower() != "https":
        violations.append(f"redirect_uri must use HTTPS, got '{redirect_uri}'")
    elif not parsed_uri.hostname:
        violations.append(
            f"redirect_uri must have a host, got '{redirect_uri}'"
        )

    if (
        algorithm is not None
        and algorithm not in FAPI2_ALLOWED_SIGNING_ALGORITHMS
    ):
        violations.append(
            f"Algorithm '{algorithm}' not allowed; "
            f"use {sorted(FAPI2_ALLOWED_SIGNING_ALGORITHMS)}"
        )

    return FAPIValidationResult(
        is_compliant=len(violations) == 0,
        violations=violations,
    )


def validate_fapi_client_config(
    *,
    has_client_authentication: bool,
    use_dpop: bool = False,
    use_mtls: bool = False,
) -> FAPIValidationResult:
    """Validate client configuration against FAPI 2.0 requirements.

    Args:
        has_client_authentication: Whether client authentication is configured
            (e.g. private_key_jwt or tls_client_auth).
        use_dpop: Whether DPoP sender-constraining is enabled.
        use_mtls: Whether mTLS sender-constraining is enabled.

    Returns:
        FAPIValidationResult with compliance status and any violations.
    """
    violations: list[str] = []

    if not has_client_authentication:
        violations.append(
            "Client authentication is required (confidential client)"
        )

    if not use_dpop and not use_mtls:
        violations.append(
            "Sender-constrained tokens required (enable DPoP or mTLS)"
        )

    return FAPIValidationResult(
        is_compliant=len(violations) == 0,
        violations=violations,
    )


def validate_fapi_discovery(
    discovery: DiscoveryDocumentResponse,
) -> FAPIValidationResult:
    """Validate a discovery document for FAPI 2.0 server support.

    Checks that the authorization server advertises capabilities
    required by FAPI 2.0.

    Args:
        discovery: A successful discovery document response.

    Returns:
        FAPIValidationResult with compliance status and any violations.
    """
    if not discovery.is_successful:
        return FAPIValidationResult(
            is_compliant=False,
            violations=["Discovery document fetch failed"],
        )

    violations: list[str] = []

    # Check supported grant types include authorization_code
    grants = discovery.grant_types_supported
    if grants is not None and "authorization_code" not in grants:
        violations.append(
            "Server does not support authorization_code grant type"
        )

    # Check token endpoint auth methods for strong client auth
    auth_methods = discovery.token_endpoint_auth_methods_supported
    fapi_auth_methods = {
        "private_key_jwt",
        "tls_client_auth",
        "self_signed_tls_client_auth",
    }
    if auth_methods is not None:
        supported = set(auth_methods) & fapi_auth_methods
        if not supported:
            violations.append(
                "Server does not support FAPI-compliant client auth "
                "(private_key_jwt or tls_client_auth)"
            )

    # Check signing algorithms
    algs = discovery.id_token_signing_alg_values_supported
    if algs is not None:
        fapi_algs = set(algs) & FAPI2_ALLOWED_SIGNING_ALGORITHMS
        if not fapi_algs:
            violations.append(
                "Server does not support FAPI-compliant signing algorithms "
                f"({sorted(FAPI2_ALLOWED_SIGNING_ALGORITHMS)})"
            )

    return FAPIValidationResult(
        is_compliant=len(violations) == 0,
        violations=violations,
    )


__all__ = [
    "FAPI2_ALLOWED_SIGNING_ALGORITHMS",
    "FAPI2_REQUIRED_PKCE_METHOD",
    "FAPI2_REQUIRED_RESPONSE_TYPE",
    "FAPIValidationResult",
    "validate_fapi_authorization_request",
    "validate_fapi_client_config",
    "validate_fapi_discovery",
]
