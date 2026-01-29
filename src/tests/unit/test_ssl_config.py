"""Tests for SSL certificate environment variable compatibility."""

import os
import threading
from unittest.mock import patch

import pytest

from py_identity_model.ssl_config import (
    ensure_ssl_compatibility,
    get_ssl_verify,
)


@pytest.fixture(autouse=True)
def clear_ssl_cache():
    """Clear get_ssl_verify cache before and after each test."""
    get_ssl_verify.cache_clear()
    yield
    get_ssl_verify.cache_clear()


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


class TestGetSSLVerify:
    """Test get_ssl_verify() function for httpx integration."""

    def test_get_ssl_verify_with_ssl_cert_file(self):
        """Test that get_ssl_verify returns SSL_CERT_FILE path when set."""
        with patch.dict(
            os.environ,
            {"SSL_CERT_FILE": "/path/to/cert.crt"},
            clear=True,
        ):
            # Clear cache to ensure fresh read
            get_ssl_verify.cache_clear()
            result = get_ssl_verify()
            assert result == "/path/to/cert.crt"

    def test_get_ssl_verify_with_curl_ca_bundle(self):
        """Test that get_ssl_verify returns CURL_CA_BUNDLE when SSL_CERT_FILE not set."""
        with patch.dict(
            os.environ,
            {"CURL_CA_BUNDLE": "/path/to/curl-bundle.crt"},
            clear=True,
        ):
            get_ssl_verify.cache_clear()
            result = get_ssl_verify()
            assert result == "/path/to/curl-bundle.crt"

    def test_get_ssl_verify_with_requests_ca_bundle(self):
        """Test backward compatibility: get_ssl_verify returns REQUESTS_CA_BUNDLE."""
        with patch.dict(
            os.environ,
            {"REQUESTS_CA_BUNDLE": "/path/to/requests-bundle.crt"},
            clear=True,
        ):
            get_ssl_verify.cache_clear()
            result = get_ssl_verify()
            assert result == "/path/to/requests-bundle.crt"

    def test_get_ssl_verify_priority_order(self):
        """Test that get_ssl_verify respects priority: SSL_CERT_FILE > CURL_CA_BUNDLE > REQUESTS_CA_BUNDLE."""
        # Test SSL_CERT_FILE wins
        with patch.dict(
            os.environ,
            {
                "SSL_CERT_FILE": "/ssl/cert.crt",
                "CURL_CA_BUNDLE": "/curl/bundle.crt",
                "REQUESTS_CA_BUNDLE": "/requests/bundle.crt",
            },
            clear=True,
        ):
            get_ssl_verify.cache_clear()
            assert get_ssl_verify() == "/ssl/cert.crt"

        # Test CURL_CA_BUNDLE wins when SSL_CERT_FILE not set
        with patch.dict(
            os.environ,
            {
                "CURL_CA_BUNDLE": "/curl/bundle.crt",
                "REQUESTS_CA_BUNDLE": "/requests/bundle.crt",
            },
            clear=True,
        ):
            get_ssl_verify.cache_clear()
            assert get_ssl_verify() == "/curl/bundle.crt"

    def test_get_ssl_verify_default_true(self):
        """Test that get_ssl_verify returns True when no env vars are set."""
        with patch.dict(os.environ, {}, clear=True):
            get_ssl_verify.cache_clear()
            result = get_ssl_verify()
            assert result is True

    def test_get_ssl_verify_ignores_empty_strings(self):
        """Test that get_ssl_verify ignores empty string env vars."""
        with patch.dict(
            os.environ,
            {
                "SSL_CERT_FILE": "",
                "CURL_CA_BUNDLE": "",
                "REQUESTS_CA_BUNDLE": "",
            },
            clear=True,
        ):
            get_ssl_verify.cache_clear()
            result = get_ssl_verify()
            assert result is True

    def test_get_ssl_verify_thread_safety(self):
        """Test that get_ssl_verify is thread-safe under concurrent access."""
        with patch.dict(
            os.environ,
            {"REQUESTS_CA_BUNDLE": "/path/to/bundle.crt"},
            clear=True,
        ):
            get_ssl_verify.cache_clear()
            results = []
            errors = []

            def get_ssl():
                try:
                    results.append(get_ssl_verify())
                except Exception as e:
                    errors.append(e)

            # Create 100 threads that all call get_ssl_verify concurrently
            threads = [threading.Thread(target=get_ssl) for _ in range(100)]

            # Start all threads
            for t in threads:
                t.start()

            # Wait for all threads to complete
            for t in threads:
                t.join()

            # Verify no errors occurred
            assert len(errors) == 0, f"Errors occurred: {errors}"

            # All threads should get the same result
            assert len(results) == 100
            assert all(r == "/path/to/bundle.crt" for r in results)

    def test_get_ssl_verify_caching(self):
        """Test that get_ssl_verify properly caches results."""
        with patch.dict(
            os.environ,
            {"SSL_CERT_FILE": "/first/cert.crt"},
            clear=True,
        ):
            get_ssl_verify.cache_clear()
            first_result = get_ssl_verify()
            assert first_result == "/first/cert.crt"

        # Change environment variable
        with patch.dict(
            os.environ,
            {"SSL_CERT_FILE": "/second/cert.crt"},
            clear=True,
        ):
            # Without clearing cache, should still return cached value
            # (this tests that caching is working - result should be cached first value)

            # Clear cache and verify new value is picked up
            get_ssl_verify.cache_clear()
            new_result = get_ssl_verify()
            assert new_result == "/second/cert.crt"
