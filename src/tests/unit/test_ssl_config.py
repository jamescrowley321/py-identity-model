"""Tests for SSL certificate environment variable compatibility."""

import os
from unittest.mock import patch

from py_identity_model.ssl_config import ensure_ssl_compatibility


class TestSSLConfig:
    """Test SSL configuration backward compatibility."""

    def test_requests_ca_bundle_sets_ssl_cert_file(self):
        """Test that REQUESTS_CA_BUNDLE sets SSL_CERT_FILE when SSL_CERT_FILE is not set."""
        with patch.dict(
            os.environ,
            {"REQUESTS_CA_BUNDLE": "/path/to/ca-bundle.crt"},
            clear=True,
        ):
            ensure_ssl_compatibility()
            assert os.environ.get("SSL_CERT_FILE") == "/path/to/ca-bundle.crt"

    def test_ssl_cert_file_not_overridden(self):
        """Test that existing SSL_CERT_FILE is not overridden."""
        with patch.dict(
            os.environ,
            {
                "SSL_CERT_FILE": "/existing/cert.crt",
                "REQUESTS_CA_BUNDLE": "/other/ca-bundle.crt",
            },
            clear=True,
        ):
            ensure_ssl_compatibility()
            # SSL_CERT_FILE should remain unchanged
            assert os.environ.get("SSL_CERT_FILE") == "/existing/cert.crt"

    def test_curl_ca_bundle_not_overridden(self):
        """Test that CURL_CA_BUNDLE is respected when SSL_CERT_FILE is not set."""
        with patch.dict(
            os.environ,
            {
                "CURL_CA_BUNDLE": "/curl/ca-bundle.crt",
                "REQUESTS_CA_BUNDLE": "/requests/ca-bundle.crt",
            },
            clear=True,
        ):
            ensure_ssl_compatibility()
            # SSL_CERT_FILE should not be set because CURL_CA_BUNDLE is already set
            # and httpx will use CURL_CA_BUNDLE
            assert "SSL_CERT_FILE" not in os.environ

    def test_no_env_vars_set(self):
        """Test that no environment variables are set when none exist."""
        with patch.dict(os.environ, {}, clear=True):
            ensure_ssl_compatibility()
            assert "SSL_CERT_FILE" not in os.environ

    def test_ssl_cert_file_priority(self):
        """Test that SSL_CERT_FILE has highest priority."""
        with patch.dict(
            os.environ,
            {
                "SSL_CERT_FILE": "/ssl/cert.crt",
                "CURL_CA_BUNDLE": "/curl/ca-bundle.crt",
                "REQUESTS_CA_BUNDLE": "/requests/ca-bundle.crt",
            },
            clear=True,
        ):
            ensure_ssl_compatibility()
            # SSL_CERT_FILE should remain unchanged
            assert os.environ.get("SSL_CERT_FILE") == "/ssl/cert.crt"
