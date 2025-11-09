# Development Guide for py-identity-model

This guide helps developers and AI assistants understand the development workflow, requirements, and best practices for this project.

---

## Package Management

### Use uv Exclusively

This project uses [uv](https://docs.astral.sh/uv/) for all package operations. **Do not use pip, pipenv, poetry, or conda.**

#### Setup
```bash
# Install uv if not already installed
curl -LsSf https://astral.sh/uv/install.sh | sh

# Create virtual environment and install dependencies
uv venv
uv sync --all-packages  # Installs main library + dev dependencies + examples
```

#### Adding Dependencies
```bash
# Production dependency
uv add "package-name>=1.0.0"

# Development dependency
uv add --group dev "package-name>=1.0.0"
```

#### Running Commands
Always use `make` targets or `uv run` commands. **Never run Python directly.**

```bash
# Using Make (preferred)
make test
make lint
make build-dist

# Using uv run
uv run pytest src/tests -v
uv run pre-commit run -a
```

---

## Testing Requirements

**ALL tests must pass before ANY commit. No exceptions.**

### Test Commands

#### 1. Unit Tests (Fastest - Required Before Every Commit)
```bash
make test-unit
```
- 143 unit tests, completes in ~15 seconds
- No network calls, fully isolated
- Use during active development for fast feedback
- Location: `src/tests/unit/`

#### 2. Integration Tests (Required Before PR Merge)

**Ory Integration Tests** (External Service)
```bash
make test-integration-ory
```
- Tests against Ory identity provider
- Requires valid Ory credentials in `.env`
- Run sequentially to avoid rate limiting
- Must pass: 100%

**Local Integration Tests** (Docker Required)
```bash
make test-integration-local
```
- Tests against local IdentityServer
- Uses `.env.local` configuration
- Requires Docker containers running
- For local development workflow

#### 3. Example Tests
```bash
make test-examples
```
- Validates all examples work correctly
- Tests Docker compose examples
- Requires Docker
- Must pass: 100%

#### 4. Complete Test Suite
```bash
make test-all
```
- Runs `make test` + `make test-examples`
- Complete validation before PR merge

### Test Performance

**Parallel Execution:**
- Unit tests use `-n auto` (22 workers) for speed
- ~15 seconds for 143 tests

**Sequential Execution:**
- Integration tests run sequentially to avoid HTTP 429 rate limiting from external APIs
- Multiple parallel requests to Ory trigger rate limits

**During Development:**
1. Use `make test-unit` for fast feedback (~15s)
2. Run `make test-integration-ory` before committing
3. Run `make test-examples` before PR (if examples modified)

---

## Pre-commit Hooks

**Pre-commit must pass before ANY commit.**

```bash
# Run manually (recommended before committing)
make lint
# or
uv run pre-commit run -a
```

The pre-commit configuration includes:
- **ruff** - Python linting with auto-fix
- **ruff-format** - Code formatting
- **pyrefly** - Type checking

Location: `.pre-commit-config.yaml`

---

## Development Workflow

### 1. Always Create a Feature Branch

**NEVER commit directly to main.**

```bash
# Create feature branch
git checkout -b feat/your-feature-name
# or for fixes:
git checkout -b fix/bug-description
# or for docs:
git checkout -b docs/documentation-update
```

### Branch Naming Conventions
- `feat/` - New features (e.g., `feat/async-support`)
- `fix/` - Bug fixes (e.g., `fix/ssl-verification`)
- `docs/` - Documentation (e.g., `docs/update-readme`)
- `refactor/` - Code refactoring (e.g., `refactor/http-client`)
- `test/` - Test improvements (e.g., `test/thread-safety`)
- `chore/` - Maintenance (e.g., `chore/update-dependencies`)

### 2. Making Changes

```bash
# Make code changes
# ... edit code ...

# REQUIRED: Run tests before committing
make test-unit              # Fast unit tests
make test-integration-ory   # Integration tests
make lint                   # Pre-commit hooks

# If all pass, commit
git add .
git commit -m "feat: add new feature"
git push origin feat/your-feature-name
```

### 3. Commit Message Format

Follow [Angular commit message format](https://github.com/angular/angular/blob/main/CONTRIBUTING.md#-commit-message-format) for automated versioning:

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:** `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

**Examples:**
```bash
git commit -m "feat(discovery): add OIDC discovery endpoint support"
git commit -m "fix(token): handle expired tokens correctly"
git commit -m "docs: update API documentation"
git commit -m "test: add thread safety tests"
```

**Version Bumps:**
- `feat:` commits → minor version bump
- `fix:` commits → patch version bump
- `BREAKING CHANGE:` in commit body → major version bump

---

## Code Quality Standards

### Thread Safety

**All code must be thread-safe** for use in multi-threaded web applications (FastAPI, Flask, Django).

**Requirements:**
- Use `threading.Lock` for shared mutable state
- Use `@lru_cache` and `@alru_cache` (both thread-safe)
- Create new HTTP clients per request (no shared client state)
- Document thread-safety guarantees

**Testing:**
- Thread safety tests in `src/tests/unit/test_thread_safety.py`
- Tests with 50 concurrent threads

### Backward Compatibility

**Maintain 100% backward compatibility** unless it's a major version bump.

**SSL Certificate Support:**
- Support `REQUESTS_CA_BUNDLE` (legacy from requests library)
- Support `CURL_CA_BUNDLE` (curl/httpx standard)
- Support `SSL_CERT_FILE` (standard environment variable)
- Priority order: `SSL_CERT_FILE` > `CURL_CA_BUNDLE` > `REQUESTS_CA_BUNDLE`

### Code Style

- Follow ruff configuration in `pyproject.toml`
- Use type hints throughout
- Document all public APIs with docstrings
- Write tests for all new features

---

## Project Structure

```
py-identity-model/
├── src/
│   ├── py_identity_model/    # Main package
│   │   ├── aio/              # Async implementations
│   │   ├── sync/             # Sync implementations
│   │   ├── core/             # Shared core logic
│   │   ├── http_client.py    # HTTP client factory
│   │   ├── ssl_config.py     # SSL configuration
│   │   └── ...
│   └── tests/
│       ├── unit/             # Unit tests (fast, isolated)
│       └── integration/      # Integration tests (network calls)
├── examples/
│   └── fastapi/              # FastAPI example (workspace member)
├── docs/                     # Documentation
├── .claude/                  # Claude Code configuration
├── pyproject.toml            # Project config & dependencies
├── Makefile                  # Development commands
└── .pre-commit-config.yaml   # Pre-commit hooks
```

---

## Common Workflows

### Before Every Commit

**CRITICAL: Always run before committing:**

```bash
# 1. Run unit tests (required)
make test-unit

# 2. Run pre-commit hooks (required)
make lint

# 3. Run integration tests (required)
make test-integration-ory

# 4. If you modified examples (optional)
make test-examples
```

**Required Checklist:**
- ✅ Unit tests pass (`make test-unit`)
- ✅ Pre-commit hooks pass (`make lint`)
- ✅ Integration tests pass (`make test-integration-ory`)
- ✅ All modified files are staged

### If Tests Fail

- **DO NOT COMMIT** until all tests pass
- Fix the failing tests or code causing failures
- Re-run the full test suite
- Verify pre-commit passes

### If Pre-commit Hooks Modify Files

Pre-commit hooks may auto-fix formatting issues:

1. Review the changes made by hooks
2. Stage the hook-modified files: `git add <files>`
3. Commit again

---

## Common Issues

### SSL Certificate Failures

If integration tests fail with SSL errors:
- Check SSL environment variables are set correctly
- Verify `get_ssl_verify()` is used in all HTTP client calls
- Ensure httpx clients use `verify=get_ssl_verify()`

### Pre-commit Formatting Changes

If pre-commit modifies files:
- Review the changes (usually formatting)
- Stage the modified files
- Commit again

### Docker Issues

If example tests fail:
- Check Docker is running: `docker ps`
- Verify compose file: `docker-compose -f examples/docker-compose.test.yml config`
- Check container logs: `docker logs <container-id>`

### uv Not Found

```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh
# Restart shell or source profile
```

---

## Never Skip

**NEVER:**
- Commit without running full test suite
- Skip pre-commit hooks (`--no-verify`)
- Merge PR with failing tests
- Ignore SSL/certificate configuration
- Assume code is thread-safe without verification
- Commit directly to main

**ALWAYS:**
- Create feature branches
- Run all required tests before commit
- Ensure pre-commit passes
- Maintain backward compatibility
- Document breaking changes
- Test thread safety for shared state
- Use `uv` for package management
- Use `make` or `uv run` for commands

---

## Quick Reference

### Essential Commands

```bash
# Setup
make ci-setup

# Development cycle (run before every commit)
make test-unit && make test-integration-ory && make lint

# Add dependency
uv add "package-name>=1.0.0"

# Run specific test
uv run pytest src/tests/unit/test_file.py::test_function -v

# Build and publish (CI handles this)
make build-dist
make upload-dist
```

### File Locations

- `pyproject.toml` - Project configuration and dependencies
- `Makefile` - Common development tasks
- `uv.lock` - Locked dependency versions
- `src/py_identity_model/` - Source code
- `src/tests/` - Test files
- `.claude/` - Claude Code configuration
- `docs/` - Documentation

---

## Security Guidelines

- Never commit secrets or API keys
- Use environment variables for configuration
- Validate all inputs
- Use secure defaults
- Keep dependencies updated

---

## Getting Help

- Check project documentation in `docs/`
- Review test files for usage examples
- Create GitHub issue for bugs or feature requests
- Review this guide and `README.md`

---

**Remember:** This project follows strict quality standards. All tests must pass, all pre-commit hooks must pass, and backward compatibility must be maintained. Use `uv` for all package operations and always work on feature branches.
