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

### 2. Automatic Publishing to GitHub Releases

When you push a pre-release tag, GitHub Actions automatically:
1. Builds the distribution packages (wheel and source distribution)
2. Creates a GitHub pre-release
3. Attaches the distribution files as release assets
4. Provides installation instructions in the release notes

**Workflow file:** `.github/workflows/publish-prerelease.yml`

**Note:** Pre-releases are published to GitHub Releases only, not PyPI or TestPyPI. This provides:
- Direct installation from GitHub without TestPyPI complexity
- No dependency on TestPyPI's limited storage and retention policies
- Simpler installation commands for downstream testing

### 3. Installing from GitHub Releases

Once published, you have several options for installing the pre-release:

**Option 1: Install from GitHub Release (Recommended)**

This installs the pre-built wheel directly from the GitHub release:

```bash
# Using pip
pip install https://github.com/jamescrowley321/py-identity-model/releases/download/2.0.0-rc.1/py_identity_model-2.0.0rc1-py3-none-any.whl

# Using uv
uv pip install https://github.com/jamescrowley321/py-identity-model/releases/download/2.0.0-rc.1/py_identity_model-2.0.0rc1-py3-none-any.whl
```

**Option 2: Install from Git Tag**

This builds the package from source at the specified tag:

```bash
# Using pip
pip install git+https://github.com/jamescrowley321/py-identity-model.git@2.0.0-rc.1

# Using uv
uv pip install git+https://github.com/jamescrowley321/py-identity-model.git@2.0.0-rc.1
```

**Option 3: Install in Editable Mode for Development**

For active development and testing:

```bash
git clone https://github.com/jamescrowley321/py-identity-model.git
cd py-identity-model
git checkout 2.0.0-rc.1
pip install -e .
```

**Finding the Wheel URL:**

1. Go to the [Releases page](https://github.com/jamescrowley321/py-identity-model/releases)
2. Find the pre-release version
3. Copy the link to the `.whl` file from the Assets section
4. The release notes will also include the exact installation command

### 4. Testing in a Clean Environment

Always test pre-releases in a clean virtual environment:

```bash
# Create a test environment
python -m venv test-env
source test-env/bin/activate  # On Windows: test-env\Scripts\activate

# Install the pre-release (Option 1 - from GitHub release)
pip install https://github.com/jamescrowley321/py-identity-model/releases/download/2.0.0-rc.1/py_identity_model-2.0.0rc1-py3-none-any.whl

# Or Option 2 - from git tag
pip install git+https://github.com/jamescrowley321/py-identity-model.git@2.0.0-rc.1

# Run your tests
python your_test_script.py
```

### 5. Testing in a Real Application

To test in an existing application:

```bash
# In your application directory
cd /path/to/your/app

# Install pre-release (Option 1 - from GitHub release)
pip install https://github.com/jamescrowley321/py-identity-model/releases/download/2.0.0-rc.1/py_identity_model-2.0.0rc1-py3-none-any.whl

# Or Option 2 - from git tag
pip install git+https://github.com/jamescrowley321/py-identity-model.git@2.0.0-rc.1

# Test your application
pytest
# or
python manage.py test  # Django
# or
python -m flask run    # Flask

# When done, reinstall stable version
pip install --force-reinstall py-identity-model
```

## Pre-release Checklist

Before creating a pre-release:

- [ ] All tests passing locally (`make test-unit`, `make test-integration-ory`)
- [ ] CHANGELOG updated with new features and breaking changes
- [ ] Documentation updated
- [ ] Version number follows semantic versioning
- [ ] Breaking changes clearly documented
- [ ] Migration guide updated (if needed)

## GitHub Releases vs PyPI

### GitHub Releases (Pre-releases)
- **URL:** https://github.com/jamescrowley321/py-identity-model/releases
- **Purpose:** Testing package distribution before official release
- **Retention:** Releases can be deleted or updated as needed
- **Usage:** Pre-release testing only
- **Installation:** Direct URL to wheel file or git tag

### PyPI (Official Releases)
- **URL:** https://pypi.org/
- **Purpose:** Official package distribution
- **Retention:** Packages are permanent (cannot be deleted)
- **Usage:** Production use
- **Installation:** Standard `pip install py-identity-model`

## Troubleshooting

### "Package not found" or 404 Error

If you get a 404 error when installing from GitHub:

```bash
# Verify the release exists
# Go to: https://github.com/jamescrowley321/py-identity-model/releases

# Check the exact wheel filename in the release assets
# The filename format is: py_identity_model-{version}-py3-none-any.whl
# Note: Version may have dashes converted (e.g., 2.0.0-rc.1 becomes 2.0.0rc1)

# Correct example:
pip install https://github.com/jamescrowley321/py-identity-model/releases/download/2.0.0-rc.1/py_identity_model-2.0.0rc1-py3-none-any.whl
```

### Version Already Exists

To create a new pre-release, increment the pre-release number:
- `2.0.0-rc.1` → `2.0.0-rc.2`
- `2.0.0-alpha.1` → `2.0.0-alpha.2`

GitHub Releases can be deleted if needed, but it's better to create new versions.

### Git Install Fails

If installing from git tag fails:

```bash
# Make sure git is installed
git --version

# Try with verbose output to see the error
pip install -v git+https://github.com/jamescrowley321/py-identity-model.git@2.0.0-rc.1

# Alternative: Install from the wheel URL instead
```

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
