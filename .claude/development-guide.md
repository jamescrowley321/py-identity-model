# Development Guide for py-identity-model

This guide helps Claude Code understand the development workflow and requirements for this project.

## Testing Requirements

**ALL tests must pass before ANY commit. No exceptions.**

### Test Commands

#### Quick Tests (Development)

1. **Unit Tests Only** (Fastest - ~0.5s)
   ```bash
   make test-unit
   ```
   - Runs only unit tests (no network calls)
   - 126 tests, completes in ~0.5 seconds
   - Use during active development for fast feedback
   - Location: `src/tests/unit/`

2. **All Tests**
   ```bash
   make test
   ```
   - Runs all unit + integration tests
   - Use before committing
   - Location: `src/tests/`

#### Integration Tests

3. **Integration Tests with Parallelization**
   ```bash
   make test-integration
   ```
   - Runs integration tests with parallel execution (`-n auto`)
   - Faster for network-bound tests
   - Uses pytest-xdist to run tests in parallel

4. **Ory Integration Tests**
   ```bash
   make test-integration-ory
   ```
   - Tests against Ory identity provider
   - Requires valid Ory credentials in `.env`
   - Must pass: 100%

5. **Local Integration Tests**
   ```bash
   make test-integration-local
   ```
   - Tests against local identity server
   - Uses `.env.local` configuration file
   - Requires local Docker containers running

#### Example Tests

6. **Example Tests**
   ```bash
   make test-examples
   ```
   - Validates all examples work correctly
   - Tests Docker compose examples
   - Runs `examples/run-tests.sh`
   - Must pass: 100%

#### Complete Test Suite

7. **All Tests + Examples**
   ```bash
   make test-all
   ```
   - Runs `make test` + `make test-examples`
   - Complete validation before PR merge

### Test Performance

The test suite uses **selective parallelization** to optimize speed while avoiding rate limits:

**Parallel Execution:**
- **Unit tests** (`make test-unit`): Use `-n auto` (22 workers)
  - ~1.4 seconds for 126 tests
  - No external dependencies, safe to parallelize

- **Full test suite** (`make test`): Use `-n auto`
  - Combines unit tests (parallel) + integration tests
  - Optimized for CI/CD pipelines

**Sequential Execution:**
- **Integration tests** (`make test-integration`, `make test-integration-ory`): Run sequentially
  - **Reason:** Avoid HTTP 429 rate limiting from external APIs (Ory)
  - Multiple parallel requests trigger rate limits
  - Sequential execution prevents failures

**Performance Summary:**
- Unit tests: ~1.4s (parallel across 22 workers)
- Integration tests: Sequential to avoid rate limits
- Powered by pytest-xdist

**During development:**
- Use `make test-unit` for fastest feedback loop (~1.4s)
- Run `make test` before committing (includes all tests)
- Run `make test-integration-ory` only when testing Ory integration

### Pre-commit Hooks

**Pre-commit must pass before ANY commit.**

```bash
pre-commit run --all-files
```

The pre-commit configuration includes:
- **ruff** (legacy alias) - Python linting
- **ruff format** - Python code formatting
- **pyrefly check** - Additional Python checks

Location: `.pre-commit-config.yaml`

## Development Workflow

### Making Changes

1. Make code changes
2. Run `make test` - verify it passes
3. Run `make test-integration-ory` - verify it passes
4. Run `make test-examples` - verify it passes
5. Run `pre-commit run --all-files` - verify it passes
6. Only then commit the changes

### If Tests Fail

- **DO NOT COMMIT** until all tests pass
- Fix the failing tests or the code causing failures
- Re-run the full test suite
- Verify pre-commit passes

### Git Commit Workflow

When making commits:
```bash
git add <files>
# Pre-commit hooks run automatically
# If hooks fail, fix issues and re-stage
git commit -m "message"
```

If pre-commit hooks modify files (e.g., formatting):
- The commit will be blocked
- Review the changes made by hooks
- Stage the hook-modified files: `git add <files>`
- Commit again

## Test Environment

### Integration Tests Requirements

Integration tests require:
- Valid `TEST_DISCO_ADDRESS` environment variable
- SSL certificates properly configured
- Network access to identity providers

### Docker for Examples

Example tests require:
- Docker and docker-compose installed
- Containers defined in `examples/docker-compose.test.yml`

## Code Quality Standards

### Thread Safety

**All code must be thread-safe** for use in multi-threaded web applications (FastAPI, Flask, Django).

Key requirements:
- Use `threading.Lock` for shared mutable state
- Use `@lru_cache` (which is thread-safe) for caching
- Create new HTTP clients per request (no shared client state)
- Document thread-safety guarantees

### Backward Compatibility

**Maintain 100% backward compatibility** with previous versions unless it's a major version bump.

For SSL certificates:
- Support `REQUESTS_CA_BUNDLE` (legacy from requests library)
- Support `CURL_CA_BUNDLE` (curl/httpx standard)
- Support `SSL_CERT_FILE` (standard environment variable)
- Priority order: `SSL_CERT_FILE` > `CURL_CA_BUNDLE` > `REQUESTS_CA_BUNDLE`

### Code Style

- Follow ruff configuration in `pyproject.toml`
- Line length: 79 characters
- Use type hints throughout
- Document all public APIs with docstrings

## Important Files

- `pyproject.toml` - Project configuration, dependencies, tool settings
- `Makefile` - Test and build commands
- `.pre-commit-config.yaml` - Pre-commit hook configuration
- `src/tests/` - All test files
- `examples/` - Example code and Docker configurations

## Common Issues

### SSL Certificate Failures

If integration tests fail with SSL errors:
- Check that SSL environment variables are set correctly
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
- Check container logs: `docker-compose logs`

## Never Skip

**NEVER:**
- Commit without running full test suite
- Skip pre-commit hooks (--no-verify)
- Merge PR with failing tests
- Ignore SSL/certificate configuration
- Assume code is thread-safe without verification

**ALWAYS:**
- Run all three test commands before commit
- Ensure pre-commit passes
- Maintain backward compatibility
- Document breaking changes
- Test thread safety for shared state
