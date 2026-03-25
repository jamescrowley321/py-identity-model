"""Unit tests for DiscoveryPolicy and DiscoveryEndpoint."""

import pytest

from py_identity_model import DiscoveryDocumentRequest, DiscoveryPolicy
from py_identity_model.core.discovery_policy import (
    is_loopback,
    parse_discovery_url,
    validate_url_scheme,
)
from py_identity_model.core.validators import (
    validate_https_url_with_policy,
    validate_issuer_with_policy,
)
from py_identity_model.exceptions import ConfigurationException


@pytest.mark.unit
class TestDiscoveryPolicy:
    def test_default_policy(self):
        policy = DiscoveryPolicy()
        assert policy.require_https is True
        assert policy.allow_http_on_loopback is True
        assert policy.validate_issuer is True
        assert policy.validate_endpoints is True
        assert policy.require_key_set is True
        assert policy.additional_endpoint_base_addresses == []
        assert policy.authority is None

    def test_relaxed_policy(self):
        policy = DiscoveryPolicy(
            require_https=False,
            validate_issuer=False,
        )
        assert policy.require_https is False
        assert policy.validate_issuer is False


@pytest.mark.unit
class TestIsLoopback:
    def test_localhost(self):
        assert is_loopback("localhost") is True

    def test_ipv4_loopback(self):
        assert is_loopback("127.0.0.1") is True

    def test_ipv6_loopback(self):
        assert is_loopback("::1") is True

    def test_127_x(self):
        assert is_loopback("127.0.0.2") is True
        assert is_loopback("127.1.2.3") is True

    def test_not_loopback(self):
        assert is_loopback("example.com") is False
        assert is_loopback("192.168.1.1") is False
        assert is_loopback("10.0.0.1") is False


@pytest.mark.unit
class TestParseDiscoveryUrl:
    def test_base_url(self):
        result = parse_discovery_url("https://auth.example.com")
        assert (
            result.url
            == "https://auth.example.com/.well-known/openid-configuration"
        )
        assert result.authority == "https://auth.example.com"

    def test_full_wellknown_url(self):
        result = parse_discovery_url(
            "https://auth.example.com/.well-known/openid-configuration"
        )
        assert (
            result.url
            == "https://auth.example.com/.well-known/openid-configuration"
        )
        assert result.authority == "https://auth.example.com"

    def test_with_path(self):
        result = parse_discovery_url("https://auth.example.com/tenant1")
        assert "/.well-known/openid-configuration" in result.url
        assert result.authority == "https://auth.example.com"

    def test_empty_url(self):
        with pytest.raises(ConfigurationException, match="empty"):
            parse_discovery_url("")

    def test_no_scheme(self):
        with pytest.raises(ConfigurationException, match="scheme"):
            parse_discovery_url("auth.example.com")

    def test_no_host(self):
        with pytest.raises(ConfigurationException, match="host"):
            parse_discovery_url("https://")

    def test_trailing_slash(self):
        result = parse_discovery_url("https://auth.example.com/")
        assert (
            result.url
            == "https://auth.example.com/.well-known/openid-configuration"
        )


@pytest.mark.unit
class TestValidateUrlScheme:
    def test_https_always_ok(self):
        policy = DiscoveryPolicy()
        validate_url_scheme("https://auth.example.com", policy)

    def test_http_rejected_by_default(self):
        policy = DiscoveryPolicy()
        with pytest.raises(ConfigurationException, match="HTTPS"):
            validate_url_scheme("http://auth.example.com", policy)

    def test_http_allowed_on_loopback(self):
        policy = DiscoveryPolicy(allow_http_on_loopback=True)
        validate_url_scheme("http://localhost:5000", policy)
        validate_url_scheme("http://127.0.0.1:8080", policy)

    def test_http_rejected_on_loopback_when_disabled(self):
        policy = DiscoveryPolicy(allow_http_on_loopback=False)
        with pytest.raises(ConfigurationException, match="HTTPS"):
            validate_url_scheme("http://localhost:5000", policy)

    def test_http_allowed_when_https_not_required(self):
        policy = DiscoveryPolicy(require_https=False)
        validate_url_scheme("http://auth.example.com", policy)


@pytest.mark.unit
class TestValidateIssuerWithPolicy:
    def test_none_policy_uses_strict(self):
        validate_issuer_with_policy("https://auth.example.com", None)

    def test_none_policy_rejects_http(self):
        with pytest.raises(ConfigurationException, match="HTTPS"):
            validate_issuer_with_policy("http://auth.example.com", None)

    def test_policy_disables_issuer_validation(self):
        policy = DiscoveryPolicy(validate_issuer=False)
        validate_issuer_with_policy("http://anything.com", policy)

    def test_policy_disabled_still_requires_non_empty(self):
        policy = DiscoveryPolicy(validate_issuer=False)
        with pytest.raises(ConfigurationException, match="required"):
            validate_issuer_with_policy("", policy)


@pytest.mark.unit
class TestValidateHttpsUrlWithPolicy:
    def test_none_policy_uses_strict(self):
        validate_https_url_with_policy(
            "https://auth.example.com/token", "token_endpoint", None
        )

    def test_policy_relaxed_allows_http(self):
        policy = DiscoveryPolicy(require_https=False)
        validate_https_url_with_policy(
            "http://auth.example.com/token", "token_endpoint", policy
        )

    def test_policy_loopback_allows_http(self):
        policy = DiscoveryPolicy()
        validate_https_url_with_policy(
            "http://localhost:8080/token", "token_endpoint", policy
        )

    def test_policy_rejects_http_non_loopback(self):
        policy = DiscoveryPolicy()
        with pytest.raises(ConfigurationException, match="HTTPS"):
            validate_https_url_with_policy(
                "http://auth.example.com/token", "token_endpoint", policy
            )

    def test_policy_validates_endpoints_disabled(self):
        policy = DiscoveryPolicy(validate_endpoints=False)
        validate_https_url_with_policy("not-even-a-url", "whatever", policy)

    def test_empty_url_skipped(self):
        policy = DiscoveryPolicy()
        validate_https_url_with_policy("", "optional_endpoint", policy)


@pytest.mark.unit
class TestDiscoveryDocumentRequestWithPolicy:
    def test_request_without_policy(self):
        req = DiscoveryDocumentRequest(address="https://auth.example.com")
        assert req.policy is None

    def test_request_with_policy(self):
        policy = DiscoveryPolicy(require_https=False)
        req = DiscoveryDocumentRequest(
            address="http://localhost:8080", policy=policy
        )
        assert req.policy is not None
        assert req.policy.require_https is False
