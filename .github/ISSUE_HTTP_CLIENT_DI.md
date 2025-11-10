# Enhancement: Add Dependency Injection Support for HTTP Client Management

## Summary

Currently, the async HTTP client uses a module-level global singleton pattern with lazy initialization. While this works and is common in Python libraries, it has limitations around testability, flexibility, and control over client lifecycle. This issue proposes adding **optional** dependency injection patterns while maintaining backward compatibility with the existing global singleton approach.

## Current Architecture

### Async Client (aio/http_client.py)
```python
# Module-level globals
_async_http_client: httpx.AsyncClient | None = None
_async_client_creation_lock = threading.Lock()
_async_client_cleanup_lock: asyncio.Lock | None = None

def get_async_http_client() -> httpx.AsyncClient:
    """Returns global singleton client."""
    global _async_http_client
    # Double-checked locking pattern
    ...

async def close_async_http_client() -> None:
    """Closes global singleton client."""
    global _async_http_client, _async_client_cleanup_lock
    ...
```

### Sync Client (sync/http_client.py)
```python
# Thread-local storage (not a true global)
_thread_local = threading.local()

def get_http_client() -> httpx.Client:
    """Returns thread-local client."""
    if not hasattr(_thread_local, "client"):
        _thread_local.client = httpx.Client(...)
    return _thread_local.client
```

**Note**: The sync client pattern is actually good - thread-local storage provides isolation per thread without true globals.

## Problems with Current Global Async Client

1. **Hidden Dependencies**: Functions implicitly depend on module-level state
2. **Testing Difficulties**: Requires special `_reset_async_http_client()` functions
3. **Limited Control**: Users can't easily:
   - Use multiple clients with different configurations
   - Manage client lifecycle explicitly
   - Mock/stub clients for testing
4. **Shared State**: Single global client shared across all event loops/tasks
5. **Import-Time Side Effects**: Global state initialized during module import

## Proposed Solutions

We should support **three patterns** while keeping the current global approach as the default for backward compatibility:

### Option 1: Dependency Injection (Recommended for Libraries)

**Best for**: Library users who want explicit control

```python
# New class-based API (alongside existing functions)
class AsyncHTTPClient:
    """
    Managed async HTTP client with retry logic.

    Example:
        # Pattern 1: Explicit lifecycle management
        client = AsyncHTTPClient()
        disco = await get_discovery_document(address, http_client=client)
        await client.close()

        # Pattern 2: Context manager (auto-cleanup)
        async with AsyncHTTPClient() as client:
            disco = await get_discovery_document(address, http_client=client)
    """

    def __init__(
        self,
        client: httpx.AsyncClient | None = None,
        timeout: float | None = None,
        verify: bool | str = True,
    ):
        """
        Initialize HTTP client manager.

        Args:
            client: Optional existing httpx.AsyncClient to wrap. If None, creates one.
            timeout: Request timeout in seconds (default: from HTTP_TIMEOUT env or 30.0)
            verify: SSL verification setting (default: from environment)
        """
        self._client = client or self._create_client(timeout, verify)
        self._owned = client is None  # Track if we created it

    @staticmethod
    def _create_client(timeout: float | None, verify: bool | str) -> httpx.AsyncClient:
        """Create new HTTP client with configuration."""
        return httpx.AsyncClient(
            verify=verify if verify is not True else get_ssl_verify(),
            timeout=timeout or get_timeout(),
            follow_redirects=True,
        )

    @property
    def client(self) -> httpx.AsyncClient:
        """Access underlying httpx.AsyncClient."""
        return self._client

    async def close(self) -> None:
        """Close client if we own it."""
        if self._owned and self._client:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self):
        """Support async context manager."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Auto-cleanup on context exit."""
        await self.close()


# Update all async functions to accept optional client parameter
async def get_discovery_document(
    address: str,
    http_client: AsyncHTTPClient | None = None,  # NEW parameter
) -> DiscoveryDocumentResponse:
    """
    Fetch OpenID Connect discovery document.

    Args:
        address: Discovery endpoint URL
        http_client: Optional HTTP client. If None, uses global singleton.

    Example:
        # Uses global singleton (backward compatible)
        disco = await get_discovery_document("https://example.com")

        # Explicit client management
        async with AsyncHTTPClient() as client:
            disco = await get_discovery_document(
                "https://example.com",
                http_client=client
            )
    """
    if http_client is None:
        # Backward compatibility: use global singleton
        client = get_async_http_client()
    else:
        client = http_client.client

    return await _fetch_discovery_document(client, address)
```

**Benefits**:
- ✅ Explicit dependencies (no hidden globals)
- ✅ Easy to test (pass mock client)
- ✅ Multiple clients with different configs
- ✅ Backward compatible (http_client=None uses global)

**Usage Examples**:
```python
# Example 1: Share client across multiple calls (efficient)
async with AsyncHTTPClient() as client:
    disco = await get_discovery_document(
        "https://accounts.google.com",
        http_client=client
    )
    jwks = await get_jwks(
        disco.jwks_uri,
        http_client=client
    )
    token = await request_client_credentials_token(
        disco.token_endpoint,
        client_id="...",
        client_secret="...",
        http_client=client,
    )

# Example 2: Custom timeout for specific operation
slow_client = AsyncHTTPClient(timeout=60.0)
result = await long_running_operation(http_client=slow_client)
await slow_client.close()

# Example 3: Testing with mock
mock_client = AsyncHTTPClient(client=MockAsyncClient())
result = await get_discovery_document(
    "https://test.example.com",
    http_client=mock_client
)
```

### Option 2: Context Manager Pattern (Automatic Lifecycle)

**Best for**: Applications that want automatic cleanup

```python
class AsyncHTTPClientManager:
    """
    Global HTTP client manager with automatic lifecycle management.

    Example:
        # Application startup
        async with AsyncHTTPClientManager() as http_manager:
            # Set as global default
            set_default_http_client(http_manager)

            # Run application
            await run_app()

            # Automatic cleanup on exit
    """

    def __init__(self):
        self._client: httpx.AsyncClient | None = None
        self._lock = asyncio.Lock()

    async def get_client(self) -> httpx.AsyncClient:
        """Get or create the HTTP client (lazy initialization)."""
        if self._client is None:
            async with self._lock:
                if self._client is None:
                    self._client = httpx.AsyncClient(
                        verify=get_ssl_verify(),
                        timeout=get_timeout(),
                        follow_redirects=True,
                    )
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client is not None:
            async with self._lock:
                if self._client is not None:
                    await self._client.aclose()
                    self._client = None

    async def __aenter__(self):
        """Enter async context."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Exit async context and auto-cleanup."""
        await self.close()


# Global default manager (optional)
_default_manager: AsyncHTTPClientManager | None = None

def set_default_http_client(manager: AsyncHTTPClientManager) -> None:
    """Set default HTTP client manager for the application."""
    global _default_manager
    _default_manager = manager

async def get_default_http_client() -> httpx.AsyncClient:
    """Get client from default manager or create temporary one."""
    if _default_manager:
        return await _default_manager.get_client()
    else:
        # Fallback to current singleton behavior
        return get_async_http_client()
```

**Benefits**:
- ✅ Automatic cleanup via context manager
- ✅ Scoped lifecycle management
- ✅ Works well with application frameworks

**Usage Example**:
```python
async def main():
    """Application entry point."""
    async with AsyncHTTPClientManager() as http_manager:
        # Set as default for entire application
        set_default_http_client(http_manager)

        # Run application
        await run_application()

        # Automatic cleanup when exiting context
```

### Option 3: App-Level Singleton (Best for Web Applications)

**Best for**: FastAPI, Starlette, and other async web frameworks

```python
# FastAPI example
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.

    Handles startup and shutdown of shared resources.
    """
    # Startup: Create shared HTTP client
    http_client = AsyncHTTPClient()
    app.state.http_client = http_client

    yield  # Application runs

    # Shutdown: Close HTTP client
    await http_client.close()

app = FastAPI(lifespan=lifespan)

@app.get("/discovery")
async def get_discovery_endpoint(request: Request, issuer: str):
    """
    Fetch discovery document endpoint.

    Uses HTTP client from app state (created at startup).
    """
    disco = await get_discovery_document(
        address=f"{issuer}/.well-known/openid-configuration",
        http_client=request.app.state.http_client,
    )
    return disco
```

**Benefits**:
- ✅ Single client per application instance
- ✅ Framework-managed lifecycle
- ✅ No manual cleanup needed
- ✅ Works with dependency injection frameworks

**Starlette Example**:
```python
from starlette.applications import Starlette
from starlette.routing import Route

async def startup():
    """Create HTTP client at startup."""
    app.state.http_client = AsyncHTTPClient()

async def shutdown():
    """Close HTTP client at shutdown."""
    await app.state.http_client.close()

async def discovery_endpoint(request):
    """Use HTTP client from app state."""
    disco = await get_discovery_document(
        address=request.query_params["issuer"],
        http_client=request.app.state.http_client,
    )
    return JSONResponse(disco.as_dict())

app = Starlette(
    routes=[Route("/discovery", discovery_endpoint)],
    on_startup=[startup],
    on_shutdown=[shutdown],
)
```

## Implementation Plan

### Phase 1: Add New Classes (Backward Compatible)
1. Add `AsyncHTTPClient` class to `aio/http_client.py`
2. Add `AsyncHTTPClientManager` class to `aio/http_client.py`
3. Keep existing `get_async_http_client()` and `close_async_http_client()` functions
4. No breaking changes

### Phase 2: Update Public API Functions
1. Add optional `http_client` parameter to all async functions:
   - `get_discovery_document()`
   - `get_jwks()`
   - `request_client_credentials_token()`
   - `validate_token()`
2. Default to `None` (uses global singleton for backward compatibility)
3. Add examples to docstrings

### Phase 3: Documentation
1. Add usage guide for all three patterns
2. Add migration guide for users wanting to move away from globals
3. Document testing best practices with mocks
4. Add FastAPI/Starlette integration examples

### Phase 4: Deprecation Path (Future Major Version)
1. Deprecate global singleton functions in favor of dependency injection
2. Add deprecation warnings
3. Update all examples to use new patterns
4. Eventually remove globals in next major version (v2.0.0)

## Testing Strategy

### Unit Tests
```python
# Test with injected client
async def test_discovery_with_custom_client():
    """Test discovery with custom HTTP client."""
    mock_response = httpx.Response(200, json={...})
    mock_client = MockAsyncClient(mock_response)

    async with AsyncHTTPClient(client=mock_client) as http_client:
        disco = await get_discovery_document(
            "https://test.example.com",
            http_client=http_client,
        )

    assert disco.issuer == "https://test.example.com"

# Test backward compatibility
async def test_discovery_without_client():
    """Test discovery still works without explicit client (global)."""
    disco = await get_discovery_document("https://accounts.google.com")
    assert disco.issuer is not None
```

### Integration Tests
```python
# Test client reuse across multiple calls
async def test_shared_client():
    """Test sharing client across multiple operations."""
    async with AsyncHTTPClient() as client:
        # All operations share same client (efficient)
        disco = await get_discovery_document(issuer, http_client=client)
        jwks = await get_jwks(disco.jwks_uri, http_client=client)
        token = await request_token(..., http_client=client)

        # Verify same underlying httpx.AsyncClient was used
        assert client.client.is_closed is False

    # Verify cleanup
    assert client.client.is_closed is True
```

## Breaking Changes

**None** - This proposal maintains full backward compatibility:
- Existing code using `get_async_http_client()` continues to work
- New optional parameters default to `None` (use global singleton)
- No changes to existing function signatures (only additions)
- Global singleton remains as default behavior

## Related Issues

- Thread safety of async HTTP client initialization (#XXX)
- Sync vs async HTTP client architecture (#XXX)
- Better test isolation for HTTP client (#XXX)

## References

- [Python Dependency Injection Patterns](https://python-dependency-injector.ets-labs.org/)
- [FastAPI Lifespan Events](https://fastapi.tiangolo.com/advanced/events/)
- [Starlette Lifecycle](https://www.starlette.io/lifespan/)
- [HTTPX Advanced Usage](https://www.python-httpx.org/advanced/)

## Questions for Discussion

1. Should we add all three patterns or start with just dependency injection?
2. What's the timeline for deprecating the global singleton (if at all)?
3. Should `AsyncHTTPClient` wrap `httpx.AsyncClient` or extend it?
4. Do we need a similar pattern for the sync client, or is thread-local sufficient?

---

**Priority**: Medium
**Effort**: Medium (2-3 weeks)
**Impact**: High (improves testability and flexibility)
**Breaking**: No (fully backward compatible)
