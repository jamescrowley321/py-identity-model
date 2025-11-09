# Pre-release Testing Guide

This guide explains how to create and test pre-release versions of py-identity-model before publishing to PyPI.

## Overview

Pre-releases allow you to:
- Test new features in realistic environments before official release
- Get feedback from early adopters
- Verify packaging and distribution works correctly
- Test installation in various environments

## Pre-release Workflow

### 1. Create a Pre-release Tag

Pre-release tags follow semantic versioning with pre-release identifiers:

```bash
# Release candidate (recommended for final testing)
git tag 2.0.0-rc.1
git push origin 2.0.0-rc.1

# Alpha release (early testing, unstable)
git tag 2.0.0-alpha.1
git push origin 2.0.0-alpha.1

# Beta release (feature complete, needs testing)
git tag 2.0.0-beta.1
git push origin 2.0.0-beta.1
```

**Tag Format:**
- `X.Y.Z-rc.N` - Release candidate
- `X.Y.Z-alpha.N` - Alpha version
- `X.Y.Z-beta.N` - Beta version

### 2. Automatic Publishing to TestPyPI

When you push a pre-release tag, GitHub Actions automatically:
1. Runs all tests (unit + integration)
2. Builds the distribution packages
3. Publishes to [TestPyPI](https://test.pypi.org/)
4. Creates a GitHub pre-release with installation instructions

**Workflow file:** `.github/workflows/publish-prerelease.yml`

### 3. Installing from TestPyPI

Once published, install the pre-release version for testing:

```bash
# Using pip
pip install --index-url https://test.pypi.org/simple/ \
            --extra-index-url https://pypi.org/simple/ \
            py-identity-model==2.0.0-rc.1

# Using uv (recommended)
uv pip install --index-url https://test.pypi.org/simple/ \
               --extra-index-url https://pypi.org/simple/ \
               py-identity-model==2.0.0-rc.1
```

**Note:** The `--extra-index-url` is required because dependencies are installed from regular PyPI.

### 4. Testing in a Clean Environment

Always test pre-releases in a clean virtual environment:

```bash
# Create a test environment
python -m venv test-env
source test-env/bin/activate  # On Windows: test-env\Scripts\activate

# Install the pre-release
pip install --index-url https://test.pypi.org/simple/ \
            --extra-index-url https://pypi.org/simple/ \
            py-identity-model==2.0.0-rc.1

# Run your tests
python your_test_script.py
```

### 5. Testing in a Real Application

To test in an existing application:

```bash
# In your application directory
cd /path/to/your/app

# Create a backup of requirements
cp requirements.txt requirements.txt.backup

# Install pre-release
pip install --index-url https://test.pypi.org/simple/ \
            --extra-index-url https://pypi.org/simple/ \
            py-identity-model==2.0.0-rc.1

# Test your application
pytest
# or
python manage.py test  # Django
# or
python -m flask run    # Flask

# Restore original requirements when done
pip install -r requirements.txt.backup
```

## Pre-release Checklist

Before creating a pre-release:

- [ ] All tests passing locally (`make test-unit`, `make test-integration-ory`)
- [ ] CHANGELOG updated with new features and breaking changes
- [ ] Documentation updated
- [ ] Version number follows semantic versioning
- [ ] Breaking changes clearly documented
- [ ] Migration guide updated (if needed)

## TestPyPI vs PyPI

### TestPyPI (Pre-releases)
- **URL:** https://test.pypi.org/
- **Purpose:** Testing package distribution before official release
- **Retention:** Packages may be deleted over time
- **Usage:** Pre-release testing only

### PyPI (Official Releases)
- **URL:** https://pypi.org/
- **Purpose:** Official package distribution
- **Retention:** Packages are permanent (cannot be deleted)
- **Usage:** Production use

## Troubleshooting

### "Package not found" Error

If you get a "package not found" error:

```bash
# Make sure you're using the correct index URL
pip install --index-url https://test.pypi.org/simple/ \
            --extra-index-url https://pypi.org/simple/ \
            py-identity-model==2.0.0-rc.1

# Check if the version exists
pip index versions py-identity-model --index-url https://test.pypi.org/simple/
```

### Version Already Exists

TestPyPI allows overwriting versions, but it's better to increment:
- `2.0.0-rc.1` → `2.0.0-rc.2`
- `2.0.0-alpha.1` → `2.0.0-alpha.2`

### Dependencies Not Installing

Always include `--extra-index-url https://pypi.org/simple/` to install dependencies from PyPI.

## Promoting Pre-release to Stable

Once testing is complete:

1. **Create a stable release tag:**
   ```bash
   git tag 2.0.0
   git push origin 2.0.0
   ```

2. **GitHub Actions will automatically:**
   - Run all tests
   - Build distribution
   - Publish to PyPI (not TestPyPI)
   - Create GitHub release

3. **Update CHANGELOG:**
   - Move "Unreleased" section to versioned release
   - Add release date

## Examples

### Testing Async Features

```python
# test_prerelease_async.py
import asyncio
from py_identity_model import DiscoveryDocumentRequest
from py_identity_model.aio import get_discovery_document

async def test_async_discovery():
    request = DiscoveryDocumentRequest(
        address="https://demo.duendesoftware.com/.well-known/openid-configuration"
    )
    response = await get_discovery_document(request)

    assert response.is_successful
    print(f"Issuer: {response.issuer}")
    print(f"JWKS URI: {response.jwks_uri}")

asyncio.run(test_async_discovery())
```

### Testing Thread Safety

```python
# test_thread_safety.py
from concurrent.futures import ThreadPoolExecutor
from py_identity_model import TokenValidationConfig, validate_token

def validate_token_wrapper(token):
    config = TokenValidationConfig(
        perform_disco=True,
        audience="my-api"
    )
    return validate_token(
        jwt=token,
        token_validation_config=config,
        disco_doc_address="https://auth.example.com"
    )

# Test with 50 concurrent threads
with ThreadPoolExecutor(max_workers=50) as executor:
    tokens = [get_test_token() for _ in range(100)]
    results = list(executor.map(validate_token_wrapper, tokens))

print(f"Successfully validated {len(results)} tokens concurrently")
```

## Resources

- [TestPyPI](https://test.pypi.org/)
- [PyPI Packaging Guide](https://packaging.python.org/)
- [Semantic Versioning](https://semver.org/)
- [py-identity-model Documentation](https://github.com/jamescrowley321/py-identity-model/tree/main/docs)

## Getting Help

- Open an issue: https://github.com/jamescrowley321/py-identity-model/issues
- Check existing discussions
- Review CHANGELOG for breaking changes
