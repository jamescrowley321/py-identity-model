# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

py-identity-model is a production-grade OIDC/OAuth2.0 helper library for Python that provides JWT decoding, token generation, and validation. It offers both synchronous and asynchronous APIs with full OpenID Connect Discovery 1.0 and RFC 7517 (JWKS) compliance.

**Key Design Philosophy:**
- **Dual API Design**: Synchronous (`py_identity_model`) and asynchronous (`py_identity_model.aio`) APIs with shared business logic
- **Thread Safety**: Sync API uses thread-local storage for HTTP clients; async API uses singleton with lock protection
- **Modular Architecture**: Clean separation between HTTP layer, business logic (`core/`), and API surface
- **Production Ready**: Used in production for years as foundation for Flask/FastAPI middleware

**Future Vision:**
- **Monorepo Evolution**: Project will evolve into a monorepo structure with separate packages for framework-specific middleware
- **Framework Packages**: Planned packages include `fastapi-identity-model`, `flask-identity-model`, etc.
- **Code Reuse**: Examples should reuse shared code to demonstrate future package structure and minimize duplication

## Mandatory Workflow Rules

**CRITICAL: Follow these rules for every change. No exceptions.**

1. **Always work on a feature branch** — never commit directly to `main`. Create a branch from `main` before starting work:
   ```bash
   git checkout -b feat/my-feature main
   ```

2. **Always run `make lint` before committing** — this runs all pre-commit hooks (ruff lint, ruff format, pyrefly typecheck, pytest coverage). If `ruff format` modifies files, re-stage them and commit again. Do NOT use `--no-verify` to skip hooks.
   ```bash
   make lint                    # Run BEFORE every commit
   ```

3. **Always run `make test` before pushing** — ensures all unit and integration tests pass with 80% minimum coverage.

4. **Use conventional commits** — commit messages must follow the Angular convention (see Git Workflow section below). Commits to `main` trigger semantic-release version bumps.

5. **Create a PR for all changes** — push the feature branch and open a PR against `main`. PR titles **must** follow conventional commit format (e.g., `feat(discovery): add metadata support`, `fix: handle missing kid`, `ci: update actions`).

## Architecture

### Module Structure

```
src/py_identity_model/
├── sync/                    # Synchronous API implementations
│   ├── http_client.py      # Thread-local HTTP client (threading.local)
│   ├── discovery.py        # Sync discovery document operations
│   ├── jwks.py             # Sync JWKS operations
│   ├── token_client.py     # Sync token endpoint operations
│   ├── token_validation.py # Sync token validation
│   └── userinfo.py         # Sync UserInfo endpoint operations
├── aio/                     # Asynchronous API implementations
│   ├── http_client.py      # Singleton async HTTP client (lock-protected)
│   ├── discovery.py        # Async discovery document operations
│   ├── jwks.py             # Async JWKS operations
│   ├── token_client.py     # Async token endpoint operations
│   ├── token_validation.py # Async token validation
│   └── userinfo.py         # Async UserInfo endpoint operations
├── core/                    # Shared business logic (protocol-agnostic)
│   ├── models.py           # Request/Response models (dataclasses)
│   ├── discovery_logic.py  # Discovery document parsing/validation
│   ├── jwks_logic.py       # JWKS parsing/validation logic
│   ├── token_validation_logic.py  # JWT validation orchestration
│   ├── token_client_logic.py      # Token request logic
│   ├── userinfo_logic.py   # UserInfo request logic
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
   - Per-feature error handlers in `core/error_handlers.py` (e.g., `handle_discovery_error()`, `handle_token_error()`, `handle_userinfo_error()`)
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

## Git Workflow

### Conventional Commits

This project uses [Conventional Commits](https://www.conventionalcommits.org/) with Angular convention for semantic versioning automation. All commit messages must follow this format:

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Required Components:**
- **type**: The type of change (see allowed types below)
- **subject**: Short description in imperative mood (e.g., "add feature" not "added feature")

**Optional Components:**
- **scope**: Module or component affected (e.g., `discovery`, `jwks`, `token-validation`, `userinfo`)
- **body**: Detailed explanation with bullet points if needed
- **footer**: Breaking changes, issue references

**Allowed Types** (from `pyproject.toml`):
- `feat`: New feature (triggers minor version bump)
- `fix`: Bug fix (triggers patch version bump)
- `perf`: Performance improvement (triggers patch version bump)
- `docs`: Documentation changes only
- `test`: Adding or updating tests
- `build`: Build system or dependencies
- `ci`: CI/CD pipeline changes
- `chore`: Maintenance tasks, tooling
- `refactor`: Code refactoring without changing behavior
- `style`: Code style/formatting changes

**Examples:**

```bash
# Feature addition (minor version bump)
git commit -m "feat(discovery): add support for OAuth 2.0 authorization server metadata"

# Bug fix with detailed body (patch version bump)
git commit -m "$(cat <<'EOF'
fix(token-validation): handle missing kid in JWT header

- Add fallback to use first key when kid is missing
- Improve error messages for key lookup failures
- Add test coverage for missing kid scenario

Fixes #123
EOF
)"

# Breaking change (major version bump)
git commit -m "$(cat <<'EOF'
feat(api)!: remove deprecated sync-only exports

BREAKING CHANGE: Removed `get_token` function. Use `request_client_credentials_token` instead.

Migration guide:
- Replace get_token() with request_client_credentials_token()
- Update TokenRequest to ClientCredentialsTokenRequest
EOF
)"
```

**Important Notes:**
- Use the body for detailed explanations with bullet points
- Reference issue numbers in the footer
- Breaking changes must include `!` after type/scope AND `BREAKING CHANGE:` in footer
- Use heredoc syntax for multi-line commits: `git commit -m "$(cat <<'EOF' ... EOF)"`
- Pre-commit hooks will run automatically (linting, type checking, coverage)

### Branch Naming Conventions

Branch names should follow conventional commit types to maintain consistency across the codebase. Use the format:

```
<type>/<short-description>
```

**Format Rules:**
- **type**: Must match one of the allowed conventional commit types (feat, fix, docs, test, chore, etc.)
- **short-description**: Lowercase, hyphen-separated, concise description of the work
- Keep branch names under 50 characters when possible

**Allowed Types:**
- `feat/` - New features or enhancements
- `fix/` - Bug fixes
- `docs/` - Documentation-only changes
- `test/` - Adding or updating tests
- `chore/` - Maintenance, tooling, dependencies
- `refactor/` - Code refactoring
- `perf/` - Performance improvements
- `ci/` - CI/CD changes
- `build/` - Build system changes
- `style/` - Code formatting/style changes

**Examples:**

```bash
# Feature branch
git checkout -b feat/descope-integration

# Bug fix branch
git checkout -b fix/token-validation-edge-case

# Documentation branch
git checkout -b docs/add-migration-guide

# Test branch
git checkout -b test/increase-coverage

# Chore branch
git checkout -b chore/update-dependencies

# Multiple related features (use most significant type)
git checkout -b feat/add-auth0-example
```

**Branch Naming Anti-Patterns:**

❌ **Avoid:**
- Generic names: `fix/updates`, `feat/changes`
- Non-descriptive: `feat/new-stuff`
- Wrong type: `fix/add-new-feature` (should be `feat/`)
- Mixed purposes: `feat/fix-bug-and-add-feature` (create separate branches)
- Uppercase or spaces: `Feat/New-Feature`, `feat/new feature`

✅ **Prefer:**
- Specific: `fix/jwks-key-rotation-bug`
- Descriptive: `feat/auth0-fastapi-example`
- Correct type: `feat/add-introspection-endpoint`
- Single purpose: One branch per logical change
- Lowercase with hyphens: `feat/descope-integration`

**Working with Issues:**

When working on GitHub issues, optionally reference the issue number:

```bash
# With issue number
git checkout -b feat/descope-integration-158

# Or use issue number in commits instead
git checkout -b feat/descope-integration
git commit -m "feat(examples): add Descope example

Related: #158"
```

**Important:**
- Branch names should align with the primary conventional commit type in the branch
- If a branch contains multiple commit types, use the most significant type (feat > fix > chore > docs)
- Create separate branches for unrelated changes, even if they use the same commit type

## Key Implementation Details

### Adding New Features

When adding new protocol features (introspection, revocation, etc.):

1. **Define models in `core/models.py`** using dataclasses with type hints
2. **Implement business logic in `core/`** as pure functions (no I/O)
3. **Add error handler in `core/error_handlers.py`** returning the response model on failure
4. **Add response parser in `core/response_processors.py`** for HTTP response parsing
5. **Add sync wrapper in `sync/`** that calls core logic with sync HTTP client
6. **Add async wrapper in `aio/`** that calls same core logic with async HTTP client
7. **Export from `sync/__init__.py`** and `aio/__init__.py`
8. **Export from top-level `__init__.py`** (sync only, for backward compatibility)
9. **Add exception type in `exceptions.py`** inheriting from `NetworkException`
10. **Add unit tests** for both sync (`test_sync_*.py`) and async (`test_aio_*.py`) using `respx` mocks
11. **Add integration tests** in `src/tests/integration/` testing against real identity providers

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

- **Unit tests**: Use `respx` to mock HTTP in `src/tests/unit/`. Sync tests use `@respx.mock` decorator, async tests use `@pytest.mark.asyncio` class + `@respx.mock` on methods.
- **Integration tests**: Test against real identity providers in `src/tests/integration/`. Session-scoped fixtures in `conftest.py` cache discovery docs, JWKS, and tokens to avoid rate limits.
- **Coverage**: Minimum 80% coverage required (enforced by pytest, pre-commit, and SonarCloud)

### Examples and Code Reuse

Examples demonstrate framework integration patterns and should **minimize code duplication** through reuse:

**Architecture Principles:**
- **Shared Base Code**: Generic framework integration code lives in `examples/<framework>/` (e.g., `examples/fastapi/`)
- **Provider-Specific Extensions**: Provider examples (e.g., `examples/descope/`) import and extend base code
- **No Duplication**: Middleware, base dependencies, and utilities should be imported, not copied
- **Future-Ready**: This structure prepares for extraction into framework-specific packages (e.g., `fastapi-identity-model`)

**Example Structure:**

```
examples/
├── fastapi/                    # Generic FastAPI example (base)
│   ├── middleware.py          # Reusable: Token validation middleware
│   ├── dependencies.py        # Reusable: Base dependency injection
│   ├── token_refresh.py       # Reusable: Token refresh utilities
│   └── app.py                 # Generic example app
├── descope/                    # Descope-specific example (extends base)
│   ├── app.py                 # Descope-specific endpoints
│   ├── dependencies.py        # Imports base deps + adds Descope-specific deps
│   └── test_integration.py   # Descope integration tests
└── auth0/                      # Future: Auth0-specific example
    ├── app.py                 # Auth0-specific endpoints
    └── dependencies.py        # Imports base deps + adds Auth0-specific deps
```

**When Adding Provider Examples:**

1. **Identify Shared Code**: Determine what can be reused from generic example
2. **Import Base Components**: Import middleware, base dependencies from `examples.<framework>`
3. **Add Provider-Specific Code**: Only create new files for provider-unique features
4. **Document Code Reuse**: Update README to explain what's shared vs. provider-specific

**Example: Descope Dependencies**

```python
# examples/descope/dependencies.py
from examples.fastapi.dependencies import (
    get_claims,
    get_current_user,
    get_token,
    require_scope,
)

# Only define Descope-specific functions
def get_descope_roles(claims: dict = Depends(get_claims)) -> list:
    return claims.get("roles", [])

def require_descope_role(role: str):
    # Provider-specific authorization logic
    pass
```

**Benefits:**
- 📦 Reduces duplication across examples
- 🔄 Easier maintenance (fix once, applies to all)
- 🎯 Clear separation of generic vs. provider-specific code
- 🚀 Natural evolution path to framework packages

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
4. **Don't forget to close responses**: HTTP responses must be fully consumed (`response.read()` or `response.json()`) to return connections to the pool. Sync wrappers call `response.close()` explicitly.
5. **Always add type hints**: This codebase requires comprehensive type annotations for all functions and classes.

## Version Management

The project uses semantic versioning with python-semantic-release:
- Version is defined in `pyproject.toml:project.version`
- Commit messages follow Angular convention (feat:, fix:, docs:, etc.)
- Pre-releases use `-rc.N` suffix on non-main branches
- Main branch releases are stable versions

For pre-release testing, see `docs/pre-release-guide.md`.
