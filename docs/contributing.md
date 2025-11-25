# Contributing to py-identity-model

Thank you for your interest in contributing to py-identity-model! This document provides guidelines and instructions for contributing to the project.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for all contributors.

## Getting Started

### Prerequisites

- Python 3.12 or higher
- [uv](https://github.com/astral-sh/uv) for dependency management
- Git

### Development Setup

1. **Fork and clone the repository**
   ```bash
   git clone https://github.com/YOUR_USERNAME/py-identity-model.git
   cd py-identity-model
   ```

2. **Install uv** (if not already installed)
   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

3. **Create a virtual environment and install dependencies**
   ```bash
   uv venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   uv sync --all-extras
   ```

4. **Install pre-commit hooks**
   ```bash
   pre-commit install
   ```

## Development Workflow

### Code Style and Conventions

- **Linting**: We use [Ruff](https://github.com/astral-sh/ruff) for linting and formatting
- **Type Hints**: All code must include comprehensive type hints
- **Docstrings**: Use Google-style docstrings for all public classes and functions
- **Line Length**: Maximum 100 characters per line
- **Import Order**: Imports are automatically sorted by Ruff

### Running Tests

Run the full test suite:
```bash
make test
```

Run only unit tests:
```bash
make test-unit
```

Run only integration tests:
```bash
make test-integration
```

Run integration tests against local environment:
```bash
make test-integration-local
```

Run tests with coverage:
```bash
uv run pytest src/tests --cov=py_identity_model --cov-report=html -v
```

Run specific tests:
```bash
uv run pytest src/tests/test_discovery.py
uv run pytest src/tests/test_discovery.py::test_specific_function
```

### Code Formatting and Linting

Run all pre-commit checks (linting and formatting):
```bash
make lint
```

This will run Ruff for both formatting and linting checks.

### Pre-commit Hooks

Pre-commit hooks will automatically run when you commit. They will:
- Format code with Ruff
- Check for linting issues
- Validate type hints
- Check for common issues

If pre-commit fails, fix the issues and commit again.

## Making Changes

### Branch Naming

Use descriptive branch names with prefixes:
- `feat/` - New features (e.g., `feat/add-token-introspection`)
- `fix/` - Bug fixes (e.g., `fix/token-validation-bug`)
- `docs/` - Documentation changes (e.g., `docs/update-readme`)
- `refactor/` - Code refactoring (e.g., `refactor/base-classes`)
- `test/` - Test improvements (e.g., `test/add-integration-tests`)
- `chore/` - Maintenance tasks (e.g., `chore/update-dependencies`)

### Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `refactor`: Code refactoring
- `test`: Test changes
- `chore`: Maintenance tasks
- `ci`: CI/CD changes
- `perf`: Performance improvements
- `style`: Code style changes (formatting, etc.)

**Examples:**
```
feat(token): add token introspection endpoint support

fix(validation): handle missing kid in JWT header

docs(readme): add examples for token validation

test(discovery): add integration tests for discovery endpoint
```

### Pull Request Process

1. **Create a feature branch** from `main`
   ```bash
   git checkout -b feat/your-feature-name
   ```

2. **Make your changes** following the code style guidelines

3. **Write or update tests** to cover your changes
   - Unit tests for new functionality
   - Update existing tests if behavior changes
   - Aim for high test coverage

4. **Update documentation** if needed
   - Update README.md if adding new features
   - Update docstrings for changed functions/classes
   - Add examples if appropriate

5. **Run tests and linting**
   ```bash
   make test
   make lint
   ```

6. **Commit your changes** with clear commit messages

7. **Push to your fork**
   ```bash
   git push origin feat/your-feature-name
   ```

8. **Create a Pull Request** on GitHub
   - Use a clear, descriptive title
   - Reference related issues (e.g., "Closes #123")
   - Describe what changes you made and why
   - Include examples if adding new features

### Pull Request Guidelines

- **Keep PRs focused**: One feature or fix per PR
- **Write clear descriptions**: Explain what and why, not just how
- **Include tests**: All new code should have tests
- **Update documentation**: Keep docs in sync with code changes
- **Follow the style guide**: Use Ruff for consistent formatting
- **Be responsive**: Address review feedback promptly

## Testing Requirements

### Test Coverage

- Target minimum 90% code coverage
- All new features must include tests
- Bug fixes should include regression tests

### Test Types

1. **Unit Tests**: Test individual functions and classes
2. **Integration Tests**: Test interactions between components
3. **End-to-End Tests**: Test complete workflows against real providers (where feasible)

### Writing Tests

Use pytest and follow these conventions:

```python
import pytest
from py_identity_model import DiscoveryDocumentRequest, get_discovery_document


def test_discovery_document_success():
    """Test successful discovery document retrieval."""
    request = DiscoveryDocumentRequest(address="https://example.com/.well-known/openid-configuration")
    response = get_discovery_document(request)

    assert response.is_successful
    assert response.issuer is not None


def test_discovery_document_invalid_url():
    """Test discovery document with invalid URL."""
    request = DiscoveryDocumentRequest(address="invalid-url")
    response = get_discovery_document(request)

    assert not response.is_successful
    assert response.error is not None
```

## Documentation

### Docstring Format

Use Google-style docstrings:

```python
def validate_token(jwt: str, token_validation_config: TokenValidationConfig, disco_doc_address: str) -> dict:
    """Validate a JWT token against the provided configuration.

    Args:
        jwt: The JWT token string to validate.
        token_validation_config: Configuration for token validation.
        disco_doc_address: Address of the OpenID Connect discovery document.

    Returns:
        Dictionary containing the validated JWT claims.

    Raises:
        PyIdentityModelException: If token validation fails.

    Examples:
        >>> config = TokenValidationConfig(perform_disco=True, audience="my-api")
        >>> claims = validate_token(token, config, "https://auth.example.com")
        >>> print(claims["sub"])
    """
    # Implementation
```

### Building Documentation

Build the documentation locally:
```bash
mkdocs serve
```

Then visit http://127.0.0.1:8000 to view the docs.

## Release Process

### Official Releases

Releases are automated using semantic-release. Version numbers follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

When commits are pushed to the `main` branch, semantic-release automatically:
1. Analyzes commit messages to determine version bump
2. Updates version in `pyproject.toml`
3. Generates CHANGELOG
4. Creates a git tag
5. Publishes to PyPI

### Pre-releases

For testing changes before official release, create a pre-release tag:

```bash
# Create and push a pre-release tag
git tag 2.0.0-rc.1
git push origin 2.0.0-rc.1
```

**Pre-release tag formats:**
- `X.Y.Z-rc.N` - Release candidate
- `X.Y.Z-alpha.N` - Alpha version
- `X.Y.Z-beta.N` - Beta version

When you push a pre-release tag, GitHub Actions will:
1. Build distribution packages (wheel and source distribution)
2. Create a GitHub pre-release
3. Attach distribution files as release assets
4. Include installation instructions in release notes

**Installing pre-releases:**

```bash
# Option 1: From GitHub release (recommended)
pip install https://github.com/jamescrowley321/py-identity-model/releases/download/2.0.0-rc.1/py_identity_model-2.0.0rc1-py3-none-any.whl

# Option 2: From git tag
pip install git+https://github.com/jamescrowley321/py-identity-model.git@2.0.0-rc.1
```

For detailed pre-release testing instructions, see [Pre-release Testing Guide](pre-release-guide.md).

## Project Structure

```
py-identity-model/
├── src/py_identity_model/       # Main source code
│   ├── __init__.py              # Public API exports
│   ├── discovery.py             # Discovery document support
│   ├── jwks.py                  # JWKS support
│   ├── tokens.py                # Token generation
│   ├── validation.py            # Token validation
│   ├── identity.py              # Identity/Claims/Principal
│   └── ...
├── tests/                       # Test files
├── docs/                        # Documentation
├── examples/                    # Example code
├── pyproject.toml              # Project configuration
├── README.md                   # Project readme
└── CONTRIBUTING.md             # This file
```

## Roadmap

See the [project roadmap](py_identity_model_roadmap.md) and [GitHub issues](https://github.com/jamescrowley321/py-identity-model/issues) for planned features and current priorities.

Current focus areas:
- **v0.1.0 - Foundation**: Testing, documentation, base classes
- **v0.2.0 - Core Protocols**: Authorization code flow, refresh tokens, token exchange
- **v0.3.0 - Advanced Endpoints**: Introspection, revocation, userinfo
- **v0.4.0 - Modern Security**: DPoP, PAR, JAR, FAPI 2.0
- **v0.5.0 - Async & Examples**: Async support, middleware examples, provider integrations

## Getting Help

- **Issues**: Open an issue for bugs or feature requests
- **Discussions**: Use GitHub Discussions for questions and ideas
- **Documentation**: Check the [docs](https://jamescrowley321.github.io/py-identity-model/)

## Recognition

Contributors will be recognized in the project documentation and release notes. Thank you for helping make py-identity-model better!

## License

By contributing to py-identity-model, you agree that your contributions will be licensed under the Apache License 2.0.
