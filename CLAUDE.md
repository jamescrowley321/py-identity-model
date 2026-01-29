# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

py-identity-model is a production-grade OIDC/OAuth2.0 helper library for Python that provides JWT decoding, token generation, and validation. It offers both synchronous and asynchronous APIs with full OpenID Connect Discovery 1.0 and RFC 7517 (JWKS) compliance.

**Key Design Philosophy:**
- **Dual API Design**: Synchronous (`py_identity_model`) and asynchronous (`py_identity_model.aio`) APIs with shared business logic
- **Thread Safety**: Sync API uses thread-local storage for HTTP clients; async API uses singleton with lock protection
- **Modular Architecture**: Clean separation between HTTP layer, business logic (`core/`), and API surface
- **Production Ready**: Used in production for years as foundation for Flask/FastAPI middleware

## Architecture

### Module Structure

```
src/py_identity_model/
├── sync/                    # Synchronous API implementations
│   ├── http_client.py      # Thread-local HTTP client (threading.local)
│   ├── discovery.py        # Sync discovery document operations
│   ├── jwks.py             # Sync JWKS operations
│   ├── token_client.py     # Sync token endpoint operations
│   └── token_validation.py # Sync token validation
├── aio/                     # Asynchronous API implementations
│   ├── http_client.py      # Singleton async HTTP client (lock-protected)
│   ├── discovery.py        # Async discovery document operations
│   ├── jwks.py             # Async JWKS operations
│   ├── token_client.py     # Async token endpoint operations
│   └── token_validation.py # Async token validation
├── core/                    # Shared business logic (protocol-agnostic)
│   ├── models.py           # Request/Response models (dataclasses)
│   ├── discovery_logic.py  # Discovery document parsing/validation
│   ├── jwks_logic.py       # JWKS parsing/validation logic
│   ├── token_validation_logic.py  # JWT validation orchestration
│   ├── token_client_logic.py      # Token request logic
│   ├── validators.py       # Input validation utilities
│   ├── error_handlers.py   # HTTP error response handling
│   ├── parsers.py          # JSON/text parsing utilities
│   ├── response_processors.py     # Response processing utilities
│   ├── jwt_helpers.py      # JWT decoding helpers
│   └── http_utils.py       # HTTP configuration utilities
├── exceptions.py            # All exception types
├── identity.py             # ClaimsPrincipal/ClaimsIdentity models
├── ssl_config.py           # SSL certificate configuration
├── oidc_constants.py       # Protocol constants
└── jwt_claim_types.py      # Standard JWT claim names
```

### Critical Architectural Patterns

1. **HTTP Client Management**
   - **Sync API**: Each thread gets its own HTTP client via `threading.local()`. See `sync/http_client.py:get_http_client()`
   - **Async API**: Single shared client per process with lock-protected initialization. See `aio/http_client.py:get_async_http_client()`
   - Both use `httpx` with connection pooling and configurable timeouts/retries

2. **Business Logic Separation**
   - All protocol logic lives in `core/` modules and is shared between sync/async
   - Sync/async modules are thin wrappers that handle I/O and call core logic
   - Core functions are pure (no I/O) and return result objects or raise exceptions

3. **Caching Strategy**
   - Discovery documents: Cached per-process with `functools.lru_cache` (sync) and `async_lru.alru_cache` (async)
   - JWKS keys: Cached to avoid repeated fetches during token validation
   - All caches are per-process, not shared across processes

4. **Error Handling**
   - HTTP errors handled in `core/error_handlers.py:handle_http_error()`
   - Structured exceptions in `exceptions.py` (all inherit from `PyIdentityModelException`)
   - Error responses follow OIDC/OAuth2 error formats

## Development Commands

### Setup
```bash
uv sync                     # Install dependencies and sync environment
```

### Testing
```bash
# Run all tests (unit + integration)
make test

# Run only unit tests (fast, no external dependencies)
make test-unit

# Run integration tests against ORY identity provider
make test-integration-ory   # Requires environment variables (see CI)

# Run integration tests against local identity server
make test-integration-local # Requires .env.local file

# Run example integration tests (spins up Docker containers)
make test-examples

# Run all tests including examples
make test-all

# Run a single test file
uv run pytest src/tests/unit/test_discovery.py -v

# Run a specific test
uv run pytest src/tests/unit/test_discovery.py::test_function_name -v
```

**Coverage Requirements**: All test commands enforce 80% minimum coverage to align with SonarCloud quality gates.

### Linting
```bash
# Run all pre-commit hooks (ruff format, ruff check, pyrefly typecheck, coverage)
make lint

# Auto-fix linting issues
uv run ruff check --fix src/
```

### Building
```bash
# Build distribution packages
make build-dist             # Creates wheel and sdist in dist/
```

### CI Setup (for local CI simulation)
```bash
make ci-setup               # Installs uv and sets up environment
```

## Key Implementation Details

### Adding New Features

When adding new protocol features (introspection, revocation, userinfo, etc.):

1. **Define models in `core/models.py`** using dataclasses with type hints
2. **Implement business logic in `core/`** as pure functions (no I/O)
3. **Add sync wrapper in `sync/`** that calls core logic with sync HTTP client
4. **Add async wrapper in `aio/`** that calls same core logic with async HTTP client
5. **Export from `sync/__init__.py`** and `aio/__init__.py`
6. **Export from top-level `__init__.py`** (sync only, for backward compatibility)

Example structure:
```python
# core/new_feature_logic.py
def process_response(response_data: dict) -> ResultModel:
    """Pure function, no I/O"""
    pass

# sync/new_feature.py
def new_feature_sync(request: RequestModel) -> ResultModel:
    client = get_http_client()
    response = client.post(...)  # Sync I/O
    return process_response(response.json())

# aio/new_feature.py
async def new_feature_async(request: RequestModel) -> ResultModel:
    client = await get_async_http_client()
    response = await client.post(...)  # Async I/O
    return process_response(response.json())
```

### Testing Patterns

- **Unit tests**: Test business logic in `core/` with mocked data (no HTTP)
- **Integration tests**: Test against real identity providers (marked with `@pytest.mark.integration`)
- **Async tests**: Use `pytest-asyncio` with `@pytest.mark.asyncio` decorator
- **Coverage**: Minimum 80% coverage required (enforced by pytest, pre-commit, and SonarCloud)

### HTTP Configuration

Environment variables (see `core/http_utils.py`):
- `HTTP_TIMEOUT`: Request timeout in seconds (default: 30.0)
- `HTTP_RETRY_COUNT`: Max retries for rate-limited requests (default: 3)
- `HTTP_RETRY_BASE_DELAY`: Base delay for exponential backoff (default: 1.0)
- `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` / `CURL_CA_BUNDLE`: Custom CA bundle paths

### SSL/TLS Configuration

The library supports custom SSL certificates via environment variables. Priority order:
1. `SSL_CERT_FILE` (httpx native, recommended)
2. `REQUESTS_CA_BUNDLE` (backward compatibility)
3. `CURL_CA_BUNDLE` (httpx fallback)
4. System defaults

See `ssl_config.py` for implementation details.

## Common Pitfalls

1. **Don't mix sync and async**: Never call sync functions from async code or vice versa. Use the appropriate API for your context.
2. **Don't bypass core logic**: Always implement business logic in `core/` first, then wrap in sync/async layers.
3. **Don't share state between threads**: The sync API uses thread-local storage for a reason. Global state breaks thread safety.
4. **Don't forget to close responses**: HTTP responses must be fully consumed (`response.read()` or `response.json()`) to return connections to the pool.
5. **Don't hardcode timeouts in tests**: Use environment variables or test fixtures for configurable timeouts.
6. **Always add type hints**: This codebase requires comprehensive type annotations for all functions and classes.

## Version Management

The project uses semantic versioning with python-semantic-release:
- Version is defined in `pyproject.toml:project.version`
- Commit messages follow Angular convention (feat:, fix:, docs:, etc.)
- Pre-releases use `-rc.N` suffix on non-main branches
- Main branch releases are stable versions

For pre-release testing, see `docs/pre-release-guide.md`.
