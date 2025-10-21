# py-identity-model Development Guidelines

This document provides comprehensive development guidelines for the py-identity-model project, following best practices inspired by [JetBrains Junie guide](https://www.jetbrains.com/guide/ai/article/junie/).

## Package Management

### Use uv for All Package Operations

This project exclusively uses [uv](https://docs.astral.sh/uv/) for package management. **Do not use pip, pipenv, poetry, or conda.**

#### Installation
```bash
# Install uv if not already installed
curl -LsSf https://astral.sh/uv/install.sh | sh
```

#### Environment Setup
```bash
# Create virtual environment
uv venv

# Install all workspace dependencies (main library + examples)
uv sync --all-packages

# This will install:
# - Main py-identity-model library
# - Development dependencies (pytest, ruff, pyrefly, etc.)
# - Documentation dependencies (mkdocs, etc.)
# - Example dependencies (FastAPI example)
```

#### Adding Dependencies
```bash
# Add production dependency
uv add "package-name>=1.0.0"

# Add development dependency
uv add --group dev "package-name>=1.0.0"
```

## Running Python Scripts and Commands

### Use Make or uv Commands

Always use either `make` targets or direct `uv run` commands. **Never run python scripts directly.**

#### Available Make Targets
```bash
# Run tests
make test

# Run linting and formatting
make lint

# Build distribution
make build-dist

# Upload to PyPI
make upload-dist

# CI setup
make ci-setup
```

#### Direct uv Commands
```bash
# Run tests
uv run pytest src/tests -v

# Run specific test file
uv run pytest src/tests/unit/test_discovery.py -v

# Run linting
uv run pre-commit run -a

# Run Python script
uv run python -m py_identity_model.script_name

# Start Python REPL with project environment
uv run python
```

## Code Quality Standards

### Pre-commit Hooks
All commits must pass pre-commit hooks:
```bash
# Install pre-commit hooks (one-time setup)
uv run pre-commit install

# Run hooks manually
make lint
# or
uv run pre-commit run -a
```

### Code Formatting and Linting
- **Ruff**: Used for linting and formatting
- **pyrefly**: Used for type checking
- Configuration is in `pyproject.toml` and `.pre-commit-config.yaml`
- All code must pass pre-commit hooks before commit

### Testing Requirements
- **pytest**: Test framework
- Minimum test coverage: Aim for >80%
- Run tests before every commit: `make test`

#### Test Structure
```
src/tests/
├── unit/          # Unit tests (fast, isolated)
├── integration/   # Integration tests (slower, external dependencies)
└── __init__.py
```

#### Running Tests
```bash
# All tests
make test

# Unit tests only
uv run pytest src/tests/unit -v

# Integration tests only
uv run pytest src/tests/integration -v

# Specific test file
uv run pytest src/tests/unit/test_discovery.py::TestClass::test_method -v
```

## Development Workflow

### 1. Environment Setup
```bash
# Clone repository
git clone <repository-url>
cd py-identity-model

# Setup development environment
make ci-setup
# or manually:
uv venv
uv sync --all-packages
uv run pre-commit install
```

**Note**: This project uses uv workspaces. The workspace includes:
- Root package: `py-identity-model` (main library)
- Examples: `examples/fastapi` (FastAPI example with its own dependencies)

### 2. Feature Development

**IMPORTANT: Always create a new branch for any changes. Never commit directly to main.**

```bash
# ALWAYS create a feature branch before making changes
git checkout -b feature/your-feature-name
# or for fixes:
git checkout -b fix/bug-description
# or for docs:
git checkout -b docs/documentation-update

# Make changes
# ... edit code ...

# Run tests
make test

# Run linting
make lint

# Commit changes (pre-commit hooks will run automatically)
git add .
git commit -m "feat: add new feature"

# Push changes
git push origin feature/your-feature-name
```

### Branch Naming Conventions
- `feat/` - New features (e.g., `feat/add-token-introspection`)
- `fix/` - Bug fixes (e.g., `fix/token-validation-bug`)
- `docs/` - Documentation changes (e.g., `docs/update-readme`)
- `refactor/` - Code refactoring (e.g., `refactor/base-classes`)
- `test/` - Test improvements (e.g., `test/add-integration-tests`)
- `chore/` - Maintenance tasks (e.g., `chore/update-dependencies`)

### 3. Before Committing
**CRITICAL: Always run pre-commit hooks before committing.**

Pre-commit hooks will run automatically on `git commit`, but you should run them manually first to catch issues early:
```bash
make lint  # Format and lint code (runs pre-commit)
make test  # Run all tests
```

If pre-commit hooks fail during commit:
1. Review the errors shown by the hooks
2. Fix any issues identified
3. Stage the auto-fixed files if any were modified by hooks
4. Commit again

The pre-commit hooks run:
- **ruff**: Linting with auto-fix
- **ruff-format**: Code formatting
- **pyrefly**: Type checking (excludes examples/)

## Project Structure Guidelines

### Source Code Organization
```
src/
├── py_identity_model/     # Main package
│   ├── __init__.py
│   ├── client/           # Client implementations
│   ├── validation/       # Validation logic
│   ├── messages/         # Message/protocol definitions
│   └── *.py             # Core modules
└── tests/
    ├── unit/            # Unit tests
    └── integration/     # Integration tests
```

### Module Guidelines
- Use descriptive module names
- Keep modules focused on single responsibility
- Import only what you need
- Use absolute imports from package root

### Documentation
- All public functions/classes must have docstrings
- Use type hints consistently
- Keep README.md updated
- Document breaking changes in CHANGELOG.md

## CI/CD Integration

### GitHub Actions Integration
The project uses semantic release for automated versioning:
- Commits follow [Angular commit message format](https://github.com/angular/angular/blob/main/CONTRIBUTING.md#-commit-message-format)
- `feat:` commits trigger minor version bumps
- `fix:` commits trigger patch version bumps
- `BREAKING CHANGE:` in commit body triggers major version bump

### Commit Message Format
```
<type>(<scope>): <subject>

<body>

<footer>
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

Examples:
```bash
git commit -m "feat(discovery): add OIDC discovery endpoint support"
git commit -m "fix(token): handle expired tokens correctly"
git commit -m "docs: update API documentation"
```

## Security Guidelines

- Never commit secrets or API keys
- Use environment variables for configuration
- Validate all inputs
- Use secure defaults
- Keep dependencies updated

## Performance Guidelines

- Profile code for performance bottlenecks
- Use appropriate data structures
- Cache expensive operations when appropriate
- Minimize external API calls in tests

## Error Handling

- Use custom exceptions from `py_identity_model.exceptions`
- Provide meaningful error messages
- Log errors appropriately
- Handle edge cases gracefully

## Dependencies

### Adding New Dependencies

#### For the main library:
```bash
# Production dependency
uv add "package>=1.0.0,<2"

# Development dependency
uv add --group dev "package>=1.0.0"
```

#### For examples (e.g., FastAPI):
```bash
# Add to the example's pyproject.toml
cd examples/fastapi
# Edit pyproject.toml to add the dependency
# Then sync from root:
cd ../..
uv sync --all-packages
```

### Dependency Groups
- **Production**: Core runtime dependencies (main library)
- **dev**: Development tools (testing, linting, type checking)
- **docs**: Documentation generation tools
- **Workspace members**: Each example has its own dependencies

## Troubleshooting

### Common Issues

#### uv not found
```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh
# Restart shell or source profile
```

#### Import errors
```bash
# Ensure you're in virtual environment and dependencies are installed
uv pip install -r pyproject.toml
```

#### Pre-commit hook failures
```bash
# Fix formatting issues
uv run pre-commit run -a
# Commit after fixes
```

### Getting Help
- Check project documentation in `docs/`
- Review test files for usage examples
- Create GitHub issue for bugs or feature requests

---

## Quick Reference

### Essential Commands
```bash
# Setup
make ci-setup

# Development cycle
make test && make lint

# Add dependency
uv add "package-name>=1.0.0"

# Run specific test
uv run pytest src/tests/unit/test_file.py -v
```

### File Locations
- `pyproject.toml`: Project configuration and dependencies
- `Makefile`: Common development tasks
- `uv.lock`: Locked dependency versions
- `src/py_identity_model/`: Source code
- `src/tests/`: Test files

Remember: Always use `uv` for package management and `make` or `uv run` for executing Python scripts!