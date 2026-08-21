"""
Thread safety tests for py-identity-model.

These tests verify that the library can be safely used in multi-threaded
environments like FastAPI with multiple workers, Gunicorn, or Django.
"""

import concurrent.futures
from functools import lru_cache
import threading

from py_identity_model.ssl_config import get_ssl_verify
from py_identity_model.sync.http_client import (
    _reset_http_client,
    get_http_client,
)


# Test constants
CONCURRENT_CALLS = 100
EXPECTED_CACHED_RESULT = 84


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
            futures = [executor.submit(call_get_ssl_verify) for _ in range(100)]
            concurrent.futures.wait(futures)

        # No errors should occur
        assert len(errors) == 0, f"Errors occurred: {errors}"

        # All results should be identical (cached value)
        assert len(results) == CONCURRENT_CALLS
        assert all(r == results[0] for r in results), "Results should be identical"


class TestHTTPClientThreadSafety:
    """Test thread safety of HTTP client access."""

    def test_http_client_concurrent_access(self):
        """Test that HTTP client can be accessed concurrently with thread-local storage."""
        # Clear SSL verify cache to ensure we use system defaults
        # (previous tests may have set invalid SSL paths)
        get_ssl_verify.cache_clear()

        # Reset HTTP client for clean state
        _reset_http_client()

        results = []  # list of (thread_id, client_id) tuples
        errors = []
        lock = threading.Lock()

        def get_client():
            try:
                client = get_http_client()
                tid = threading.current_thread().ident
                # Append both values atomically to avoid interleaving
                with lock:
                    results.append((tid, id(client)))
            except Exception as e:
                with lock:
                    errors.append(e)

        # Access client from 50 threads concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(get_client) for _ in range(100)]
            concurrent.futures.wait(futures)

        # No errors should occur
        assert len(errors) == 0, f"Errors occurred: {errors}"

        # We should have collected 100 results
        assert len(results) == CONCURRENT_CALLS

        thread_ids = [r[0] for r in results]
        clients = [r[1] for r in results]

        # With thread-local storage, each thread gets its own client.
        # The number of unique clients should equal the number of unique threads used.
        unique_clients = len(set(clients))
        unique_threads = len(set(thread_ids))

        # Each unique thread should have its own client
        assert unique_clients == unique_threads, (
            f"Expected {unique_threads} unique clients (one per thread), got {unique_clients}"
        )

        # Verify that calls from the same thread get the same client
        thread_to_clients: dict[int, list[int]] = {}
        for tid, cid in results:
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
        assert all(r == EXPECTED_CACHED_RESULT for r in results)

        # Function should only be called once due to caching
        assert call_count == 1, "Function should only be called once (cached)"
