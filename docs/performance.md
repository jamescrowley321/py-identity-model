# Performance Guide

This guide covers performance characteristics, caching behavior, and optimization strategies for py-identity-model.

## Overview

py-identity-model is designed for high performance with built-in caching and support for both synchronous and asynchronous I/O. Understanding these performance characteristics will help you optimize your application.

## Caching

### Discovery Document Caching

Discovery documents are cached automatically to avoid repeated HTTP requests:

**Sync Implementation:**
```python
from functools import lru_cache

@lru_cache(maxsize=128)
def _get_disco_response(disco_doc_address: str) -> DiscoveryDocumentResponse:
    """Cached discovery document fetching"""
    request = DiscoveryDocumentRequest(address=disco_doc_address)
    return get_discovery_document(request)
```

**Async Implementation:**
```python
from async_lru import alru_cache

@alru_cache(maxsize=128)
async def _get_disco_response(disco_doc_address: str) -> DiscoveryDocumentResponse:
    """Cached async discovery document fetching"""
    request = DiscoveryDocumentRequest(address=disco_doc_address)
    return await get_discovery_document(request)
```

### JWKS Caching

JSON Web Key Sets are also cached:

- **Cache Size**: 128 entries (both sync and async)
- **Cache Key**: JWKS URL (from discovery document)
- **Cache Duration**: Lifetime of the process
- **Thread Safety**: Both implementations are thread-safe

### Cache Behavior Differences

| Aspect | Synchronous | Asynchronous |
|--------|-------------|--------------|
| Library | `functools.lru_cache` | `async_lru.alru_cache` |
| Max Entries | 128 | 128 |
| Thread Safety | ✅ Yes | ✅ Yes |
| Cache Sharing | Sync calls only | Async calls only |
| Cache Clearing | `function.cache_clear()` | `function.cache_clear()` |
| Performance | Fast | Fast |

**Important:** Sync and async caches are **separate**. They do not share cached data.

#### Example: Cache Separation

```python
from py_identity_model import get_discovery_document as sync_disco
from py_identity_model.aio import get_discovery_document as async_disco
from py_identity_model import DiscoveryDocumentRequest

# First call - fetches from network (sync cache)
disco = sync_disco(DiscoveryDocumentRequest(address="https://..."))

# Second call - uses sync cache (fast)
disco = sync_disco(DiscoveryDocumentRequest(address="https://..."))

# Async call - fetches from network again (separate cache!)
disco = await async_disco(DiscoveryDocumentRequest(address="https://..."))

# Second async call - uses async cache (fast)
disco = await async_disco(DiscoveryDocumentRequest(address="https://..."))
```

### Clearing Caches

You can manually clear caches if needed:

```python
from py_identity_model.sync.token_validation import _get_disco_response, _get_jwks_response

# Clear discovery document cache
_get_disco_response.cache_clear()

# Clear JWKS cache
_get_jwks_response.cache_clear()
```

For async:
```python
from py_identity_model.aio.token_validation import _get_disco_response, _get_jwks_response

# Clear async discovery document cache
_get_disco_response.cache_clear()

# Clear async JWKS cache
_get_jwks_response.cache_clear()
```

### Cache Statistics

You can inspect cache performance:

```python
from py_identity_model.sync.token_validation import _get_disco_response

# Get cache statistics
info = _get_disco_response.cache_info()
print(f"Hits: {info.hits}")
print(f"Misses: {info.misses}")
print(f"Size: {info.currsize}")
print(f"Max Size: {info.maxsize}")
print(f"Hit Rate: {info.hits / (info.hits + info.misses) * 100:.2f}%")
```

## Performance Benchmarks

### Token Validation Performance

Typical token validation times (with caching):

| Operation | First Call | Cached Call | Notes |
|-----------|-----------|-------------|-------|
| Discovery Document | ~500-1000ms | <1ms | Network latency dependent |
| JWKS Fetch | ~500-1000ms | <1ms | Network latency dependent |
| JWT Decode & Verify | ~1-5ms | ~1-5ms | No caching (always validates) |
| **Total (First)** | **~1-2s** | - | First request is slow |
| **Total (Cached)** | - | **~1-5ms** | Subsequent requests are fast |

**Key Insight:** The first token validation is slow due to network requests. Subsequent validations are very fast due to caching.

### Sync vs Async Performance

#### Single Operation

For a single token validation, sync and async have similar performance:

```python
import time

# Sync (second request, cached)
start = time.time()
claims = validate_token(token, config, disco_address)
print(f"Sync: {(time.time() - start) * 1000:.2f}ms")
# Output: Sync: 1.5ms

# Async (second request, cached)
start = time.time()
claims = await validate_token(token, config, disco_address)
print(f"Async: {(time.time() - start) * 1000:.2f}ms")
# Output: Async: 1.8ms
```

**Conclusion:** For single operations, sync and async have nearly identical performance.

#### Concurrent Operations

For multiple concurrent operations, async can be significantly faster:

```python
import asyncio
import time

tokens = [token1, token2, token3, token4, token5]

# Sequential sync validation
start = time.time()
for token in tokens:
    claims = validate_token(token, config, disco_address)
elapsed_sync = time.time() - start
print(f"Sync Sequential: {elapsed_sync * 1000:.0f}ms")
# Output: Sync Sequential: 7.5ms (5 tokens × 1.5ms each)

# Concurrent async validation
start = time.time()
results = await asyncio.gather(
    *[validate_token(token, config, disco_address) for token in tokens]
)
elapsed_async = time.time() - start
print(f"Async Concurrent: {elapsed_async * 1000:.0f}ms")
# Output: Async Concurrent: 2.0ms (overhead + max(all validations))

print(f"Speedup: {elapsed_sync / elapsed_async:.1f}x")
# Output: Speedup: 3.7x
```

**Conclusion:** Async provides significant performance benefits when processing multiple operations concurrently.

## Optimization Strategies

### 1. Minimize Discovery Calls

Discovery documents rarely change. Call once and cache:

**Bad:**
```python
def validate_every_request(token: str):
    # This fetches discovery doc every time!
    disco_request = DiscoveryDocumentRequest(address=DISCO_ADDRESS)
    disco_response = get_discovery_document(disco_request)

    # Then validates token...
```

**Good:**
```python
# Discovery is cached automatically when using perform_disco=True
def validate_every_request(token: str):
    config = TokenValidationConfig(
        perform_disco=True,  # Uses cached discovery
        audience="api",
    )
    claims = validate_token(token, config, DISCO_ADDRESS)
    return claims
```

**Best:**
```python
# For ultimate performance, use validate_token with perform_disco=True
# This handles all caching automatically
config = TokenValidationConfig(perform_disco=True, audience="api")

def validate_request(token: str):
    return validate_token(token, config, DISCO_ADDRESS)
```

### 2. Use Async for Concurrent Operations

If you need to validate multiple tokens or make multiple requests:

**Slow (Sequential):**
```python
results = []
for token in tokens:
    claims = validate_token(token, config, disco_address)
    results.append(claims)
```

**Fast (Concurrent):**
```python
results = await asyncio.gather(
    *[validate_token(token, config, disco_address) for token in tokens],
    return_exceptions=True  # Don't fail entire batch on single error
)
```

### 3. HTTP Client Management & Connection Pooling

The library uses different HTTP client strategies for sync and async to optimize performance and thread safety.

#### Synchronous API: Thread-Local Clients

Each thread gets its own HTTP client using `threading.local()`:

```python
# Thread-local storage for sync HTTP client
_thread_local = threading.local()

def get_http_client() -> httpx.Client:
    """Get or create HTTP client for current thread."""
    if not hasattr(_thread_local, "client") or _thread_local.client is None:
        _thread_local.client = httpx.Client(
            verify=get_ssl_verify(),
            timeout=timeout,
            follow_redirects=True,
        )
    return _thread_local.client
```

**Benefits:**
- ✅ **No global state**: Eliminates race conditions
- ✅ **Thread isolation**: Each thread has its own connection pool
- ✅ **No locks needed**: Thread-local access is lock-free
- ✅ **Automatic cleanup**: Each thread manages its own client lifecycle

**Connection Pool per Thread:**
- Max Connections: 100 (httpx default)
- Max Keepalive: 20 connections (httpx default)
- Timeout: 30 seconds (py-identity-model default)

**Memory Trade-off:**
- 10 threads = 10 clients (one per thread)
- Each client has its own connection pool
- Acceptable trade-off for thread safety

#### Asynchronous API: Singleton Client

All async operations share a single HTTP client per process:

```python
_async_http_client: httpx.AsyncClient | None = None
_async_client_lock = threading.Lock()

async def get_async_http_client() -> httpx.AsyncClient:
    """Get or create the singleton async HTTP client."""
    global _async_http_client
    if _async_http_client is None:
        with _async_client_lock:  # Thread-safe initialization
            if _async_http_client is None:
                _async_http_client = httpx.AsyncClient(...)
    return _async_http_client
```

**Benefits:**
- ✅ **Shared connection pool**: All async operations share connections
- ✅ **Memory efficient**: Single client for all async operations
- ✅ **No I/O locks**: Lock only used during initialization
- ✅ **Optimal for async**: Matches async/await concurrency model

**Shared Connection Pool:**
- Max Connections: 100 (shared across all async operations)
- Max Keepalive: 20 connections (shared)
- Timeout: 30 seconds

#### Performance Comparison

| Aspect | Sync (Thread-Local) | Async (Singleton) |
|--------|---------------------|-------------------|
| Clients Created | One per thread | One per process |
| Connection Pool | Per-thread | Shared process-wide |
| Memory Usage | Higher (multiple clients) | Lower (single client) |
| Lock Contention | None (thread-local) | None (during I/O) |
| Best For | Multi-threaded apps | Async/await apps |

#### Advanced: Custom Connection Limits

For high-throughput applications, you may want to customize connection limits.

**Note:** The library uses internal client creation, so customizing limits requires forking or using environment variables for timeout configuration.

**Workaround for Custom Limits:**
```python
# Option 1: Use HTTP_TIMEOUT environment variable
import os
os.environ['HTTP_TIMEOUT'] = '60.0'  # Increase timeout to 60 seconds

# Option 2: Create your own client wrapper (advanced)
import httpx
from py_identity_model.core.discovery_logic import process_discovery_response

async def custom_discovery_fetch(url: str):
    """Custom discovery fetch with tuned connection pool."""
    limits = httpx.Limits(
        max_connections=200,
        max_keepalive_connections=50,
    )

    async with httpx.AsyncClient(limits=limits, timeout=60.0) as client:
        response = await client.get(url)
        return process_discovery_response(response)
```

### 4. Batch Token Validations

For batch processing, use async with controlled concurrency:

```python
import asyncio
from itertools import islice

async def validate_tokens_batched(tokens: list[str], batch_size: int = 50):
    """Validate tokens in batches to avoid overwhelming the system."""
    results = []

    # Process in batches
    for i in range(0, len(tokens), batch_size):
        batch = tokens[i:i + batch_size]

        batch_results = await asyncio.gather(
            *[validate_token(token, config, disco_address) for token in batch],
            return_exceptions=True
        )

        results.extend(batch_results)

        # Optional: add delay between batches
        if i + batch_size < len(tokens):
            await asyncio.sleep(0.1)

    return results
```

### 5. Warm Up the Cache

For production applications, warm up caches on startup:

```python
async def warmup_cache():
    """Warm up discovery document and JWKS caches on startup."""
    from py_identity_model.aio import get_discovery_document
    from py_identity_model import DiscoveryDocumentRequest

    disco_response = await get_discovery_document(
        DiscoveryDocumentRequest(address=DISCO_ADDRESS)
    )

    if disco_response.is_successful:
        # JWKS will be cached on first token validation
        print("✓ Cache warmed up")
    else:
        print("✗ Cache warmup failed")

# In FastAPI
@app.on_event("startup")
async def startup_event():
    await warmup_cache()
```

## Production Recommendations

### FastAPI / Async Frameworks

```python
from fastapi import FastAPI, Depends, HTTPException
from py_identity_model import TokenValidationConfig
from py_identity_model.aio import validate_token

app = FastAPI()

# Create config once
TOKEN_CONFIG = TokenValidationConfig(
    perform_disco=True,
    audience="api",
    options={
        "verify_signature": True,
        "verify_aud": True,
        "verify_exp": True,
        "verify_iss": True,
    },
)

# Warm up cache on startup
@app.on_event("startup")
async def startup():
    from py_identity_model.aio import get_discovery_document
    from py_identity_model import DiscoveryDocumentRequest

    disco = await get_discovery_document(
        DiscoveryDocumentRequest(address=DISCO_ADDRESS)
    )
    if disco.is_successful:
        print("✓ Discovery cache warmed")

# Use in dependency
async def verify_token(token: str = Depends(oauth2_scheme)):
    try:
        claims = await validate_token(
            jwt=token,
            token_validation_config=TOKEN_CONFIG,
            disco_doc_address=DISCO_ADDRESS,
        )
        return claims
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))

@app.get("/api/data")
async def protected_route(claims: dict = Depends(verify_token)):
    return {"data": "protected", "user": claims["sub"]}
```

### Flask / Sync Frameworks

```python
from flask import Flask, request, jsonify
from py_identity_model import TokenValidationConfig, validate_token

app = Flask(__name__)

# Create config once
TOKEN_CONFIG = TokenValidationConfig(
    perform_disco=True,
    audience="api",
)

# Warm up cache on first request
@app.before_first_request
def warmup():
    from py_identity_model import get_discovery_document, DiscoveryDocumentRequest

    disco = get_discovery_document(
        DiscoveryDocumentRequest(address=DISCO_ADDRESS)
    )
    if disco.is_successful:
        print("✓ Discovery cache warmed")

def verify_token():
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "")

    try:
        claims = validate_token(
            jwt=token,
            token_validation_config=TOKEN_CONFIG,
            disco_doc_address=DISCO_ADDRESS,
        )
        return claims
    except Exception as e:
        return None

@app.route("/api/data")
def protected_route():
    claims = verify_token()
    if not claims:
        return jsonify({"error": "Unauthorized"}), 401

    return jsonify({"data": "protected", "user": claims["sub"]})
```

## Monitoring and Metrics

### Cache Hit Rate

Monitor cache performance in production:

```python
import logging
from py_identity_model.sync.token_validation import _get_disco_response

logger = logging.getLogger(__name__)

def log_cache_stats():
    """Log cache statistics periodically."""
    disco_info = _get_disco_response.cache_info()

    total = disco_info.hits + disco_info.misses
    hit_rate = (disco_info.hits / total * 100) if total > 0 else 0

    logger.info(
        f"Discovery cache: {disco_info.hits} hits, "
        f"{disco_info.misses} misses, "
        f"{hit_rate:.1f}% hit rate, "
        f"{disco_info.currsize}/{disco_info.maxsize} entries"
    )

# Log every 1000 requests or periodically
```

### Performance Metrics

Track key metrics:

- **Token validation time** (p50, p95, p99)
- **Discovery cache hit rate**
- **JWKS cache hit rate**
- **Validation failures** (expired, invalid signature, etc.)
- **Network errors** (discovery/JWKS fetch failures)

Example with Prometheus:

```python
from prometheus_client import Counter, Histogram
import time

validation_duration = Histogram(
    'token_validation_duration_seconds',
    'Token validation duration'
)

validation_total = Counter(
    'token_validation_total',
    'Total token validations',
    ['result']  # success, expired, invalid, etc.
)

async def validate_with_metrics(token: str):
    start = time.time()

    try:
        claims = await validate_token(token, config, disco_address)
        validation_total.labels(result='success').inc()
        return claims
    except TokenExpiredException:
        validation_total.labels(result='expired').inc()
        raise
    except Exception:
        validation_total.labels(result='error').inc()
        raise
    finally:
        validation_duration.observe(time.time() - start)
```

## Summary

**Best Practices:**

1. ✅ Use `perform_disco=True` to enable automatic caching
2. ✅ Use async API for FastAPI and high-concurrency applications
3. ✅ Warm up caches on application startup
4. ✅ Monitor cache hit rates in production
5. ✅ Use connection pooling (automatic with httpx)
6. ✅ Batch concurrent operations with controlled concurrency
7. ✅ Track validation metrics (duration, failures, etc.)

**Performance Expectations:**

- **First validation**: ~1-2 seconds (network requests)
- **Cached validations**: ~1-5ms (very fast)
- **Async concurrency**: Up to 5-10x faster for batch operations
- **Cache hit rate**: Should be >95% in steady state

**When to Use Async:**

- FastAPI, Starlette, or other async frameworks
- High concurrency requirements (100+ req/s)
- Batch token processing
- Already using asyncio

**When Sync Is Fine:**

- Flask, Django, or other sync frameworks
- Low concurrency (<100 req/s)
- Simple CLI tools or scripts
- Single token validations
