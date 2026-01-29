# py-identity-model
![Build](https://github.com/jamescrowley321/py-identity-model/workflows/Build/badge.svg)
![License](https://img.shields.io/pypi/l/py-identity-model)

OIDC/OAuth2.0 helper library for decoding JWTs and creating JWTs utilizing the `client_credentials` grant. This project has been used in production for years as the foundation of Flask/FastAPI middleware implementations.

## Installation

```bash
pip install py-identity-model
```

Or with uv:

```bash
uv add py-identity-model
```

**Requirements:** Python 3.12 or higher

### SSL Certificate Configuration

If you're working with custom SSL certificates (e.g., in corporate environments or with self-signed certificates), the library supports the following environment variables:

- **`SSL_CERT_FILE`** - Recommended for new setups (httpx native)
- **`CURL_CA_BUNDLE`** - Alternative option (also supported by httpx)
- **`REQUESTS_CA_BUNDLE`** - Legacy support for backward compatibility

```bash
export SSL_CERT_FILE=/path/to/ca-bundle.crt
# OR
export REQUESTS_CA_BUNDLE=/path/to/ca-bundle.crt
```

**Note:** For backward compatibility, if you're upgrading from an older version that used `requests`, your existing `REQUESTS_CA_BUNDLE` environment variable will continue to work automatically.

See the [Migration Guide](docs/migration-guide.md#ssl-certificate-configuration) for more details.

## Compliance Status

* ✅ **OpenID Connect Discovery 1.0** - Fully compliant with specification requirements
* ✅ **RFC 7517 (JSON Web Key)** - Fully compliant with JWK/JWKS specifications
* ✅ **JWT Validation** - Comprehensive validation with PyJWT integration
* ✅ **Client Credentials Flow** - OAuth 2.0 client credentials grant support

The library currently supports:
* ✅ Discovery endpoint with full validation
* ✅ JWKS endpoint with RFC 7517 compliance
* ✅ JWT token validation with auto-discovery
* ✅ Authorization servers with multiple active keys
* ✅ Client credentials token generation
* ✅ Comprehensive error handling and validation

For more information on token validation options, refer to the official [PyJWT Docs](https://pyjwt.readthedocs.io/en/stable/index.html)

**Note**: Does not currently support opaque tokens.

## Async/Await Support ⚡

**NEW in v1.2.0**: Full async/await support for all client operations!

py-identity-model now provides **both synchronous and asynchronous APIs**:

- **Synchronous API** (default import): Traditional blocking I/O - perfect for scripts, CLIs, Flask, Django
- **Asynchronous API** (`from py_identity_model.aio import ...`): Non-blocking I/O - perfect for FastAPI, Starlette, high-concurrency apps

```python
# Sync (default) - works as before
from py_identity_model import get_discovery_document

response = get_discovery_document(request)

# Async (new!) - for async frameworks
from py_identity_model.aio import get_discovery_document

response = await get_discovery_document(request)
```

**When to use async:**
- ✅ Async web frameworks (FastAPI, Starlette, aiohttp)
- ✅ High-concurrency applications
- ✅ Concurrent I/O operations
- ✅ Applications already using asyncio

**When to use sync:**
- ✅ Scripts and CLIs
- ✅ Traditional web frameworks (Flask, Django)
- ✅ Simple applications
- ✅ Blocking I/O is acceptable

See [examples/async_examples.py](examples/async_examples.py) for complete async examples!

## Thread Safety & Concurrency 🔒

**py-identity-model is fully thread-safe and async-safe** for use in multi-threaded, multi-worker, and async environments.

### HTTP Client Management

The library uses different strategies for sync and async clients to ensure optimal performance and thread safety:

#### Synchronous API (Thread-Local Storage)
- **Each thread gets its own HTTP client** using `threading.local()`
- **Thread-isolated connection pooling**: Connections are reused within the same thread
- **No global state**: Eliminates race conditions and lock contention
- **Automatic cleanup**: Each thread manages its own client lifecycle

```python
# Sync API - thread-safe by design
from py_identity_model import get_discovery_document, DiscoveryDocumentRequest

# Each thread gets its own client with connection pooling
response = get_discovery_document(DiscoveryDocumentRequest(address=url))
```

**Perfect for:**
- Flask with threading (`threaded=True`)
- Gunicorn/uWSGI with threaded workers
- Messaging consumers (Kafka, RabbitMQ) with thread-per-message
- Any multi-threaded application

#### Asynchronous API (Singleton with Lock Protection)
- **Single async HTTP client per process** created lazily
- **Thread-safe initialization**: Protected by `threading.Lock()`
- **Shared connection pool**: All async operations share connections efficiently
- **Optimal for async**: No locks during I/O operations

```python
# Async API - async-safe with efficient connection sharing
from py_identity_model.aio import get_discovery_document, DiscoveryDocumentRequest

# All async operations share a single client and connection pool
response = await get_discovery_document(DiscoveryDocumentRequest(address=url))
```

**Perfect for:**
- FastAPI with async endpoints
- Starlette applications
- aiohttp servers
- Any asyncio-based application

### Caching Strategy

- ✅ **Discovery documents**: Cached per process with `functools.lru_cache` (sync) and `async_lru.alru_cache` (async)
- ✅ **JWKS keys**: Cached per process for fast validation
- ✅ **SSL configuration**: Thread-safe with lock protection
- ✅ **Response bodies**: Always fully consumed and closed

### Safe for Production

**Works seamlessly with:**
- ✅ FastAPI with multiple workers (`uvicorn --workers N`)
- ✅ Gunicorn with threading or async workers
- ✅ Django with multiple worker threads
- ✅ Flask with threading enabled
- ✅ Celery/messaging workers
- ✅ Concurrent request handling

### Performance Benefits

1. **Connection pooling**: HTTP connections are reused for better performance
2. **Thread-local clients (sync)**: No lock contention between threads
3. **Shared async client**: Efficient connection sharing in async code
4. **Cached discovery/JWKS**: Reduces redundant network calls
5. **Explicit resource cleanup**: Responses are closed to prevent connection leaks

```python
# Example: Concurrent token validation in threaded environment
from concurrent.futures import ThreadPoolExecutor
from py_identity_model import validate_token, TokenValidationConfig

def validate_request(token: str) -> dict:
    config = TokenValidationConfig(perform_disco=True, audience="my-api")
    # Each thread uses its own HTTP client with connection pooling
    return validate_token(token, config, "https://issuer.example.com")

# Safe to use with multiple threads - no shared state
with ThreadPoolExecutor(max_workers=10) as executor:
    futures = [executor.submit(validate_request, token) for token in tokens]
    results = [f.result() for f in futures]
```

```python
# Example: Concurrent async token validation
import asyncio
from py_identity_model.aio import validate_token, TokenValidationConfig

async def validate_request(token: str) -> dict:
    config = TokenValidationConfig(perform_disco=True, audience="my-api")
    # All async calls share a single client and connection pool
    return await validate_token(token, config, "https://issuer.example.com")

# Safe concurrent async operations
async def main():
    results = await asyncio.gather(*[validate_request(token) for token in tokens])
```

### Key Architectural Decisions

| Component | Sync API | Async API |
|-----------|----------|-----------|
| **HTTP Client** | Thread-local (one per thread) | Singleton (one per process) |
| **Connection Pooling** | Per-thread pools | Shared process pool |
| **Thread Safety** | Isolation via thread-local | Lock-protected initialization |
| **Best For** | Multi-threaded apps | Async/await apps |

This library inspired by [Duende.IdentityModel](https://github.com/DuendeSoftware/foss/tree/main/identity-model)

From Duende.IdentityModel
> It provides an object model to interact with the endpoints defined in the various OAuth and OpenId Connect specifications in the form of:
> * types to represent the requests and responses
> * extension methods to invoke requests
> * constants defined in the specifications, such as standard scope, claim, and parameter names
> * other convenience methods for performing common identity related operations


This library aims to provide the same features in Python.

## Documentation

For detailed usage instructions, examples, and guides, please see our comprehensive documentation:

* **[Getting Started Guide](docs/getting-started.md)** - Installation, quick start, and common use cases
* **[API Documentation](docs/index.md)** - Complete API reference with examples
* **[Migration Guide](docs/migration-guide.md)** - Migrating from sync to async API
* **[Performance Guide](docs/performance.md)** - Caching, optimization, and benchmarks
* **[Pre-release Testing Guide](docs/pre-release-guide.md)** - Creating and testing pre-release versions
* **[FAQ](docs/faq.md)** - Frequently asked questions
* **[Troubleshooting Guide](docs/troubleshooting.md)** - Common issues and solutions
* **[Project Roadmap](docs/py_identity_model_roadmap.md)** - Upcoming features and development plans
* **[Integration Tests](docs/integration-tests.md)** - Testing against real identity providers
* **[Identity Server Example](docs/identity-server-example.md)** - Running the example identity server

### Compliance Documentation

* **[OpenID Connect Discovery Compliance](docs/discovery_specification_compliance_assessment.md)** - ✅ 100% compliant
* **[JWKS Specification Compliance](docs/jwks_specification_compliance_assessment.md)** - ✅ 100% compliant

## Configuration

### Environment Variables

The library supports the following environment variables for configuration:

#### HTTP Client Configuration

- **`HTTP_TIMEOUT`** - HTTP request timeout in seconds (default: 30.0)
  ```bash
  export HTTP_TIMEOUT=60.0  # Increase timeout to 60 seconds
  ```

- **`HTTP_RETRY_COUNT`** - Number of retries for rate-limited requests (default: 3)
  ```bash
  export HTTP_RETRY_COUNT=5  # Retry up to 5 times
  ```

- **`HTTP_RETRY_BASE_DELAY`** - Base delay in seconds for exponential backoff (default: 1.0)
  ```bash
  export HTTP_RETRY_BASE_DELAY=2.0  # Start with 2-second delay
  ```

#### SSL/TLS Certificate Configuration

For working with custom SSL certificates (corporate environments, self-signed certificates):

- **`SSL_CERT_FILE`** - Path to CA bundle file (recommended, httpx native)
- **`CURL_CA_BUNDLE`** - Alternative CA bundle path (also supported by httpx)
- **`REQUESTS_CA_BUNDLE`** - Legacy support for backward compatibility

```bash
# Recommended approach
export SSL_CERT_FILE=/path/to/ca-bundle.crt

# OR use legacy variable (backward compatible)
export REQUESTS_CA_BUNDLE=/path/to/ca-bundle.crt
```

**Priority Order:** `SSL_CERT_FILE` → `REQUESTS_CA_BUNDLE` → `CURL_CA_BUNDLE` → System defaults

See the [Migration Guide](docs/migration-guide.md#ssl-certificate-configuration) for more details.

## Quick Examples

### Discovery

Only a subset of fields is currently mapped.

```python
import os

from py_identity_model import DiscoveryDocumentRequest, get_discovery_document

DISCO_ADDRESS = os.environ["DISCO_ADDRESS"]

disco_doc_request = DiscoveryDocumentRequest(address=DISCO_ADDRESS)
disco_doc_response = get_discovery_document(disco_doc_request)

if disco_doc_response.is_successful:
    print(f"Issuer: {disco_doc_response.issuer}")
    print(f"Token Endpoint: {disco_doc_response.token_endpoint}")
    print(f"JWKS URI: {disco_doc_response.jwks_uri}")
else:
    print(f"Error: {disco_doc_response.error}")
```

### JWKs

```python
import os

from py_identity_model import (
    DiscoveryDocumentRequest,
    get_discovery_document,
    JwksRequest,
    get_jwks,
)

DISCO_ADDRESS = os.environ["DISCO_ADDRESS"]

disco_doc_request = DiscoveryDocumentRequest(address=DISCO_ADDRESS)
disco_doc_response = get_discovery_document(disco_doc_request)

if disco_doc_response.is_successful:
    jwks_request = JwksRequest(address=disco_doc_response.jwks_uri)
    jwks_response = get_jwks(jwks_request)

    if jwks_response.is_successful:
        print(f"Found {len(jwks_response.keys)} keys")
        for key in jwks_response.keys:
            print(f"Key ID: {key.kid}, Type: {key.kty}")
    else:
        print(f"Error: {jwks_response.error}")
```

### Basic Token Validation

Token validation validates the signature of a JWT against the values provided from an OIDC discovery document. The function will raise a `PyIdentityModelException` if the token is expired or signature validation fails.

Token validation utilizes [PyJWT](https://github.com/jpadilla/pyjwt) for work related to JWT validation. The configuration object is mapped to the input parameters of `jwt.decode`.

```python
import os

from py_identity_model import (
    PyIdentityModelException,
    TokenValidationConfig,
    validate_token,
)

DISCO_ADDRESS = os.environ["DISCO_ADDRESS"]
TEST_AUDIENCE = os.environ["TEST_AUDIENCE"]

token = get_token()  # Get the token in the manner best suited to your application

validation_options = {
    "verify_signature": True,
    "verify_aud": True,
    "verify_iat": True,
    "verify_exp": True,
    "verify_nbf": True,
    "verify_iss": True,
    "verify_sub": True,
    "verify_jti": True,
    "verify_at_hash": True,
    "require_aud": False,
    "require_iat": False,
    "require_exp": False,
    "require_nbf": False,
    "require_iss": False,
    "require_sub": False,
    "require_jti": False,
    "require_at_hash": False,
    "leeway": 0,
}

validation_config = TokenValidationConfig(
    perform_disco=True,
    audience=TEST_AUDIENCE,
    options=validation_options
)

try:
    claims = validate_token(
        jwt=token,
        token_validation_config=validation_config,
        disco_doc_address=DISCO_ADDRESS
    )
    print(f"Token validated successfully for subject: {claims.get('sub')}")
except PyIdentityModelException as e:
    print(f"Token validation failed: {e}")
```

### Token Generation

The only current supported flow is the `client_credentials` flow. Load configuration parameters in the method your application supports. Environment variables are used here for demonstration purposes.

```python
import os

from py_identity_model import (
    ClientCredentialsTokenRequest,
    ClientCredentialsTokenResponse,
    DiscoveryDocumentRequest,
    get_discovery_document,
    request_client_credentials_token,
)

DISCO_ADDRESS = os.environ["DISCO_ADDRESS"]
CLIENT_ID = os.environ["CLIENT_ID"]
CLIENT_SECRET = os.environ["CLIENT_SECRET"]
SCOPE = os.environ["SCOPE"]

# First, get the discovery document to find the token endpoint
disco_doc_response = get_discovery_document(
    DiscoveryDocumentRequest(address=DISCO_ADDRESS)
)

if disco_doc_response.is_successful:
    # Request an access token using client credentials
    client_creds_req = ClientCredentialsTokenRequest(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        address=disco_doc_response.token_endpoint,
        scope=SCOPE,
    )
    client_creds_token = request_client_credentials_token(client_creds_req)

    if client_creds_token.is_successful:
        print(f"Access Token: {client_creds_token.token['access_token']}")
        print(f"Token Type: {client_creds_token.token['token_type']}")
        print(f"Expires In: {client_creds_token.token['expires_in']} seconds")
    else:
        print(f"Token request failed: {client_creds_token.error}")
else:
    print(f"Discovery failed: {disco_doc_response.error}")
```

## Features Status

### ✅ Completed Features
* ✅ **Discovery Endpoint** - Fully compliant with OpenID Connect Discovery 1.0
* ✅ **JWKS Endpoint** - Fully compliant with RFC 7517 (JSON Web Key)
* ✅ **Token Validation** - JWT validation with auto-discovery and PyJWT integration
* ✅ **Token Endpoint** - Client credentials grant type
* ✅ **Token-to-Principal Conversion** - Convert JWTs to ClaimsPrincipal objects
* ✅ **Protocol Constants** - OIDC and OAuth 2.0 constants
* ✅ **Comprehensive Type Hints** - Full type safety throughout
* ✅ **Error Handling** - Structured exceptions and validation
* ✅ **Async/Await Support** - Full async API via `py_identity_model.aio` module (v1.2.0)
* ✅ **Modular Architecture** - Clean separation between HTTP layer and business logic (v1.2.0)

### 🚧 Upcoming Features
* Token Introspection Endpoint (RFC 7662)
* Token Revocation Endpoint (RFC 7009)
* UserInfo Endpoint
* Dynamic Client Registration (RFC 7591)
* Device Authorization Endpoint
* Additional grant types (authorization code, refresh token, device flow)
* Opaque tokens support

For detailed development plans, see the [Project Roadmap](docs/py_identity_model_roadmap.md).
