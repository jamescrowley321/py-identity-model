"""
Thread safety tests for py-identity-model.

These tests verify that the library can be safely used in multi-threaded
environments like FastAPI with multiple workers, Gunicorn, or Django.
"""

import concurrent.futures
import threading

from py_identity_model.ssl_config import get_ssl_verify


class TestSSLConfigThreadSafety:
    """Test thread safety of SSL configuration."""

    def test_get_ssl_verify_concurrent_access(self):
        """Test that get_ssl_verify can be called concurrently from multiple threads."""
        results = []
        errors = []

        def call_get_ssl_verify():
            try:
                result = get_ssl_verify()
                results.append(result)
            except Exception as e:
                errors.append(e)

        # Call from 50 threads concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [
                executor.submit(call_get_ssl_verify) for _ in range(100)
            ]
            concurrent.futures.wait(futures)

        # No errors should occur
        assert len(errors) == 0, f"Errors occurred: {errors}"

        # All results should be identical (cached value)
        assert len(results) == 100
        assert all(r == results[0] for r in results), (
            "Results should be identical"
        )

    def test_get_ssl_verify_with_env_var(self, monkeypatch):
        """Test get_ssl_verify with environment variable set."""
        test_cert_path = "/path/to/test/cert.crt"

        # Clear cache before test
        get_ssl_verify.cache_clear()

        # Set environment variable
        monkeypatch.setenv("SSL_CERT_FILE", test_cert_path)

        # Get SSL verify value
        result = get_ssl_verify()

        assert result == test_cert_path

    def test_get_ssl_verify_priority_order(self, monkeypatch):
        """Test that SSL_CERT_FILE has priority over other variables."""
        # Clear cache before test
        get_ssl_verify.cache_clear()

        # Set all three environment variables
        monkeypatch.setenv("SSL_CERT_FILE", "/path/to/ssl_cert.crt")
        monkeypatch.setenv("CURL_CA_BUNDLE", "/path/to/curl_bundle.crt")
        monkeypatch.setenv(
            "REQUESTS_CA_BUNDLE", "/path/to/requests_bundle.crt"
        )

        result = get_ssl_verify()

        # SSL_CERT_FILE should have highest priority
        assert result == "/path/to/ssl_cert.crt"

    def test_get_ssl_verify_fallback_to_curl_ca_bundle(self, monkeypatch):
        """Test fallback to CURL_CA_BUNDLE when SSL_CERT_FILE not set."""
        # Clear cache before test
        get_ssl_verify.cache_clear()

        # Only set CURL_CA_BUNDLE and REQUESTS_CA_BUNDLE
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        monkeypatch.setenv("CURL_CA_BUNDLE", "/path/to/curl_bundle.crt")
        monkeypatch.setenv(
            "REQUESTS_CA_BUNDLE", "/path/to/requests_bundle.crt"
        )

        result = get_ssl_verify()

        # CURL_CA_BUNDLE should be used
        assert result == "/path/to/curl_bundle.crt"

    def test_get_ssl_verify_fallback_to_requests_ca_bundle(self, monkeypatch):
        """Test fallback to REQUESTS_CA_BUNDLE when others not set."""
        # Clear cache before test
        get_ssl_verify.cache_clear()

        # Only set REQUESTS_CA_BUNDLE
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        monkeypatch.delenv("CURL_CA_BUNDLE", raising=False)
        monkeypatch.setenv(
            "REQUESTS_CA_BUNDLE", "/path/to/requests_bundle.crt"
        )

        result = get_ssl_verify()

        # REQUESTS_CA_BUNDLE should be used (backward compatibility)
        assert result == "/path/to/requests_bundle.crt"

    def test_get_ssl_verify_default_system_certs(self, monkeypatch):
        """Test that system certs are used when no env vars set."""
        # Clear cache before test
        get_ssl_verify.cache_clear()

        # Clear all SSL-related environment variables
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        monkeypatch.delenv("CURL_CA_BUNDLE", raising=False)
        monkeypatch.delenv("REQUESTS_CA_BUNDLE", raising=False)

        result = get_ssl_verify()

        # Should return True to use system CA bundle
        assert result is True

    def test_get_ssl_verify_cache_behavior(self, monkeypatch):
        """Test that get_ssl_verify caches results properly."""
        # Clear cache before test
        get_ssl_verify.cache_clear()

        # Set initial value
        monkeypatch.setenv("SSL_CERT_FILE", "/path/to/cert1.crt")
        result1 = get_ssl_verify()

        # Change environment variable
        monkeypatch.setenv("SSL_CERT_FILE", "/path/to/cert2.crt")
        result2 = get_ssl_verify()

        # Results should be identical (cached)
        assert result1 == result2 == "/path/to/cert1.crt"

        # Clear cache
        get_ssl_verify.cache_clear()
        result3 = get_ssl_verify()

        # After cache clear, should get new value
        assert result3 == "/path/to/cert2.crt"


class TestHTTPClientThreadSafety:
    """Test thread safety of HTTP client access."""

    def test_http_client_concurrent_access(self):
        """Test that HTTP client can be accessed concurrently with thread-local storage."""
        from py_identity_model.ssl_config import get_ssl_verify
        from py_identity_model.sync.http_client import (
            _reset_http_client,
            get_http_client,
        )

        # Clear SSL verify cache to ensure we use system defaults
        # (previous tests may have set invalid SSL paths)
        get_ssl_verify.cache_clear()

        # Reset HTTP client for clean state
        _reset_http_client()

        clients = []
        errors = []
        thread_ids = []

        def get_client():
            try:
                import threading

                client = get_http_client()
                clients.append(id(client))  # Store object ID
                thread_ids.append(threading.current_thread().ident)
            except Exception as e:
                errors.append(e)

        # Access client from 50 threads concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(get_client) for _ in range(100)]
            concurrent.futures.wait(futures)

        # No errors should occur
        assert len(errors) == 0, f"Errors occurred: {errors}"

        # We should have collected 100 client IDs
        assert len(clients) == 100

        # With thread-local storage, each thread gets its own client.
        # The number of unique clients should equal the number of unique threads used.
        unique_clients = len(set(clients))
        unique_threads = len(set(thread_ids))

        # Each unique thread should have its own client
        assert unique_clients == unique_threads, (
            f"Expected {unique_threads} unique clients (one per thread), got {unique_clients}"
        )

        # Verify that calls from the same thread get the same client
        thread_to_clients = {}
        for tid, cid in zip(thread_ids, clients, strict=True):
            if tid not in thread_to_clients:
                thread_to_clients[tid] = []
            thread_to_clients[tid].append(cid)

        # All calls from the same thread should get the same client instance
        for tid, client_ids in thread_to_clients.items():
            assert all(cid == client_ids[0] for cid in client_ids), (
                f"Thread {tid} got different client instances: {client_ids}"
            )


class TestCachingThreadSafety:
    """Test thread safety of LRU cache decorators."""

    def test_lru_cache_thread_safe(self):
        """Test that functools.lru_cache is thread-safe."""
        from functools import lru_cache

        call_count = 0
        lock = threading.Lock()

        @lru_cache(maxsize=128)
        def cached_function(x):
            nonlocal call_count
            with lock:
                call_count += 1
            return x * 2

        results = []

        def call_cached():
            result = cached_function(42)
            results.append(result)

        # Call from 100 threads
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(call_cached) for _ in range(100)]
            concurrent.futures.wait(futures)

        # All results should be correct
        assert all(r == 84 for r in results)

        # Function should only be called once due to caching
        assert call_count == 1, "Function should only be called once (cached)"
