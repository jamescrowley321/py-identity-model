"""
Discovery policy and endpoint parsing for configurable security.

Inspired by Duende IdentityModel's DiscoveryPolicy, this module provides
configurable validation for OpenID Connect discovery operations.

Default policy enforces strict HTTPS with a loopback exception for
development. Use a relaxed policy for testing environments.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
from urllib.parse import urlparse

from ..exceptions import ConfigurationException


_WELL_KNOWN_PATH = "/.well-known/openid-configuration"
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


@dataclass
class DiscoveryPolicy:
    """Configurable security policy for discovery document validation.

    Controls how strictly the library validates discovery documents
    and their endpoints. The default is strict (production-safe).

    Attributes:
        require_https: Require HTTPS for the discovery endpoint and
            all advertised endpoints. Set ``False`` for development
            against HTTP servers.
        allow_http_on_loopback: Allow HTTP when the host is
            ``localhost``, ``127.0.0.1``, or ``::1``. Only applies
            when ``require_https`` is ``True``.
        validate_issuer: Validate the ``issuer`` field in the
            discovery document.
        validate_endpoints: Validate that advertised endpoint URLs
            are well-formed.
        require_key_set: Require a ``jwks_uri`` in the discovery
            document.
        additional_endpoint_base_addresses: Extra base URLs that
            advertised endpoints are allowed to use (for multi-domain
            or CDN setups).
        authority: Expected authority (scheme + host) for endpoint
            validation. When ``None``, derived from the discovery URL.
    """

    require_https: bool = True
    allow_http_on_loopback: bool = True
    validate_issuer: bool = True
    validate_endpoints: bool = True
    require_key_set: bool = True
    additional_endpoint_base_addresses: list[str] = field(default_factory=list)
    authority: str | None = None


@dataclass
class DiscoveryEndpoint:
    """Parsed discovery endpoint URL with extracted authority.

    Attributes:
        url: The full discovery URL (with well-known path appended
            if not already present).
        authority: The scheme + host portion of the URL.
    """

    url: str
    authority: str


def is_loopback(host: str) -> bool:
    """Check if a host is a loopback address.

    Recognizes ``localhost``, ``127.0.0.1``, ``::1``, and
    ``127.x.x.x`` addresses. Uses ``ipaddress`` for safe parsing
    so that DNS names like ``127.evil.com`` are not matched.
    """
    if host in _LOOPBACK_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def parse_discovery_url(url: str) -> DiscoveryEndpoint:
    """Parse a discovery URL and extract its authority.

    If the URL does not end with the well-known path, it is appended
    automatically.

    Args:
        url: The discovery endpoint URL or base issuer URL.

    Returns:
        DiscoveryEndpoint with the full URL and extracted authority.

    Raises:
        ConfigurationException: If the URL is malformed.
    """
    if not url:
        raise ConfigurationException("Discovery URL cannot be empty")

    parsed = urlparse(url)
    if not parsed.scheme:
        raise ConfigurationException(
            f"Discovery URL must include a scheme: {url}"
        )
    if not parsed.netloc:
        raise ConfigurationException(
            f"Discovery URL must include a host: {url}"
        )

    authority = f"{parsed.scheme}://{parsed.netloc}"

    full_url = url
    if not parsed.path.rstrip("/").endswith(_WELL_KNOWN_PATH.rstrip("/")):
        full_url = url.rstrip("/") + _WELL_KNOWN_PATH

    # Normalize: strip trailing slash to avoid 404s on servers
    # that don't accept the trailing-slash variant
    full_url = full_url.rstrip("/")

    return DiscoveryEndpoint(url=full_url, authority=authority)


def validate_url_scheme(
    url: str,
    policy: DiscoveryPolicy,
) -> None:
    """Validate a URL's scheme against the discovery policy.

    Args:
        url: The URL to validate.
        policy: The discovery policy to apply.

    Raises:
        ConfigurationException: If the URL scheme violates the policy.
    """
    parsed = urlparse(url)

    if not policy.require_https:
        return

    if parsed.scheme == "https":
        return

    if parsed.scheme == "http" and policy.allow_http_on_loopback:
        host = parsed.hostname or ""
        if is_loopback(host):
            return

    raise ConfigurationException(
        f"HTTPS is required by discovery policy. "
        f"Got: {url}. Set require_https=False or use a loopback address."
    )


__all__ = [
    "DiscoveryEndpoint",
    "DiscoveryPolicy",
    "is_loopback",
    "parse_discovery_url",
    "validate_url_scheme",
]
