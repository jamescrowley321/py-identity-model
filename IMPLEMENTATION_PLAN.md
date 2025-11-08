# Implementation Plan: Quality Issues & Documentation Fixes

## Overview
This plan addresses GitHub issues #8 (Exception Handling) and #9 (Logger Integration), improves code organization in identity.py to eliminate forward references, and fixes mkdocs build failures.

---

## 1. Code Organization Improvements (identity.py)

### Current Issues
- Uses forward references (string annotations) like `List["Claim"]` because `Claim` is defined after `Identity`
- Classes are defined in order: `Identity`, `Principal`, `Claim`, `ClaimType`, `ClaimsIdentity`, `ClaimsPrincipal`
- Forward references require quotes and are less clean

### Proposed Changes: Reorder Classes

**Why Keep ABC:**
ABC provides runtime enforcement and strictness which is appropriate for py-identity-model because:
1. We control all implementations in this library
2. Runtime validation ensures subclasses implement required methods
3. Explicit inheritance makes the API clearer
4. Matches the .NET IdentityModel design philosophy (strict contracts)
5. Better for library code where we want to enforce correct implementation

### Implementation Steps

#### Step 1: Add `from __future__ import annotations` at the top
This allows us to use clean type hints without quotes:
```python
from __future__ import annotations

import abc
import enum
from typing import List, Optional
```

#### Step 2: Reorder classes logically
New order (from most basic to most complex):
1. `Claim` (no dependencies)
2. `ClaimType` (enum, no dependencies)
3. `Identity` (abstract, references `Claim`)
4. `Principal` (abstract, references `Identity`)
5. `ClaimsIdentity` (concrete, implements `Identity`)
6. `ClaimsPrincipal` (concrete, implements `Principal`)

#### Step 3: Clean up type hints
With `from __future__ import annotations` and proper ordering:
```python
# Before (with quotes):
def claims(self) -> List["Claim"]:
    ...

# After (no quotes needed):
def claims(self) -> List[Claim]:
    ...
```

### Benefits
- ✅ No forward references (cleaner code)
- ✅ Keep ABC strictness and runtime enforcement
- ✅ Logical ordering (dependencies defined first)
- ✅ Matches .NET design philosophy
- ✅ No breaking changes to public API

---

## 2. MkDocs Build Failures

### Issues Identified
```
WARNING - Doc file 'faq.md' contains a link '../CONTRIBUTING.md', but the target is not found among documentation files.
INFO - Doc file 'faq.md' contains an unrecognized relative link '../examples/', it was left as is.
INFO - Doc file 'getting-started.md' contains an unrecognized relative link '../examples/', it was left as is.
```

### Root Causes
1. **CONTRIBUTING.md**: Referenced in `faq.md` (lines 231, 303, 306) but not in docs directory
2. **../examples/**: Referenced in `faq.md` (line 149) and `getting-started.md` (line 202) - relative link outside docs directory

### Solution Options

#### Option A: Copy Files to Docs (Recommended)
- Copy `CONTRIBUTING.md` to `docs/contributing.md`
- Update references in `faq.md` and `getting-started.md`
- For examples, create `docs/examples.md` with links to GitHub examples

#### Option B: Use Absolute GitHub URLs
- Replace `../CONTRIBUTING.md` with GitHub URL
- Replace `../examples/` with GitHub examples URL

**Recommendation: Option A** - Better user experience in documentation, works offline

### Implementation Steps

#### Step 1: Copy CONTRIBUTING.md
```bash
cp CONTRIBUTING.md docs/contributing.md
```

#### Step 2: Update mkdocs.yml navigation
```yaml
nav:
  - Home: index.md
  - Getting Started: getting-started.md
  - Guides:
      - Troubleshooting: troubleshooting.md
      - FAQ: faq.md
      - Contributing: contributing.md  # Add this
  # ... rest of navigation
```

#### Step 3: Fix faq.md references
Replace all instances (lines 231, 303, 306):
```markdown
# Change from:
[CONTRIBUTING.md](../CONTRIBUTING.md)

# Change to:
[Contributing Guide](contributing.md)
```

Replace examples reference (line 149):
```markdown
# Change from:
Check the [examples directory](https://github.com/jamescrowley321/py-identity-model/tree/main/examples) in the repository.

# Keep as is OR change to:
See the [Examples](https://github.com/jamescrowley321/py-identity-model/tree/main/examples) directory for complete implementations.
```

#### Step 4: Fix getting-started.md reference
Line 202:
```markdown
# Change from:
- Check out [Examples](../examples/) for complete working examples

# Change to:
- Check out [Examples](https://github.com/jamescrowley321/py-identity-model/tree/main/examples) for complete working examples
```

#### Step 5: Verify Build
```bash
uv run --group docs mkdocs build --strict
```

Should complete without warnings.

---

## 3. Exception Handling (Issue #8)

### Proposed Exception Hierarchy

```python
# src/py_identity_model/exceptions.py

class PyIdentityModelException(Exception):
    """Base exception for all py-identity-model errors."""

    def __init__(self, message: str, details: Optional[dict] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ValidationException(PyIdentityModelException):
    """Raised when validation fails."""
    pass


class TokenValidationException(ValidationException):
    """Raised when token validation fails."""

    def __init__(self, message: str, token_part: Optional[str] = None, **kwargs):
        super().__init__(message, **kwargs)
        self.token_part = token_part  # 'header', 'payload', 'signature'


class SignatureVerificationException(TokenValidationException):
    """Raised when signature verification fails."""
    pass


class TokenExpiredException(TokenValidationException):
    """Raised when token has expired."""
    pass


class InvalidAudienceException(TokenValidationException):
    """Raised when audience validation fails."""
    pass


class InvalidIssuerException(TokenValidationException):
    """Raised when issuer validation fails."""
    pass


class NetworkException(PyIdentityModelException):
    """Raised when network operations fail."""

    def __init__(self, message: str, url: Optional[str] = None, status_code: Optional[int] = None, **kwargs):
        super().__init__(message, **kwargs)
        self.url = url
        self.status_code = status_code


class DiscoveryException(NetworkException):
    """Raised when discovery document cannot be fetched."""
    pass


class JwksException(NetworkException):
    """Raised when JWKS cannot be fetched or parsed."""
    pass


class TokenRequestException(NetworkException):
    """Raised when token request fails."""
    pass


class ConfigurationException(PyIdentityModelException):
    """Raised when configuration is invalid."""
    pass
```

### Implementation Tasks

1. **Create exceptions.py**: New file with hierarchy above
2. **Update existing code**: Replace generic exceptions with specific ones
3. **Improve error messages**: Add contextual information
4. **Update tests**: Test each exception type
5. **Document exceptions**: Add to API documentation

### Files to Update
- `src/py_identity_model/token_validation.py` - Use `TokenValidationException`, `SignatureVerificationException`, etc.
- `src/py_identity_model/discovery.py` - Use `DiscoveryException`
- `src/py_identity_model/jwks.py` - Use `JwksException`
- `src/py_identity_model/client.py` - Use `TokenRequestException`

---

## 4. Logger Integration (Issue #9)

### Logging Strategy

#### Logger Setup
```python
# src/py_identity_model/logging_config.py

import logging
from typing import Optional

# Library logger
logger = logging.getLogger("py_identity_model")
logger.addHandler(logging.NullHandler())  # Default: no output

def configure_logging(
    level: int = logging.WARNING,
    format: Optional[str] = None,
    handler: Optional[logging.Handler] = None
) -> None:
    """
    Configure logging for py-identity-model.

    Args:
        level: Logging level (e.g., logging.DEBUG)
        format: Log format string
        handler: Custom handler (defaults to StreamHandler)
    """
    if format is None:
        format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    if handler is None:
        handler = logging.StreamHandler()

    handler.setFormatter(logging.Formatter(format))
    logger.addHandler(handler)
    logger.setLevel(level)
```

#### Sensitive Data Redaction
```python
# src/py_identity_model/logging_utils.py

import re
from typing import Any, Dict

def redact_sensitive(data: Dict[str, Any]) -> Dict[str, Any]:
    """Redact sensitive information from logs."""
    sensitive_keys = {
        'client_secret', 'password', 'access_token',
        'refresh_token', 'id_token', 'Authorization'
    }

    redacted = data.copy()
    for key in redacted:
        if key in sensitive_keys:
            redacted[key] = "***REDACTED***"
        elif isinstance(redacted[key], str) and len(redacted[key]) > 100:
            # Truncate long strings (likely tokens)
            redacted[key] = redacted[key][:20] + "...***REDACTED***"

    return redacted


def redact_token(token: str) -> str:
    """Redact token for logging (show first/last 4 chars)."""
    if len(token) < 20:
        return "***REDACTED***"
    return f"{token[:4]}...{token[-4:]}"
```

### Logging Locations

#### 1. Discovery Document Fetching
```python
# In discovery.py
logger.info(f"Fetching discovery document from {redact_url(address)}")
logger.debug(f"Discovery request options: {redact_sensitive(options)}")
logger.info(f"Discovery document fetched successfully, issuer: {response.issuer}")
logger.error(f"Failed to fetch discovery document: {error}", exc_info=True)
```

#### 2. JWKS Fetching
```python
# In jwks.py
logger.info(f"Fetching JWKS from {redact_url(jwks_uri)}")
logger.debug(f"Found {len(keys)} keys in JWKS")
logger.warning(f"No matching key found for kid: {kid}")
```

#### 3. Token Validation
```python
# In token_validation.py
logger.info("Starting token validation")
logger.debug(f"Token header: {header}")
logger.debug(f"Validation options: {options}")
logger.info("Token signature verified successfully")
logger.info(f"Token valid for subject: {claims.get('sub')}")
logger.error(f"Token validation failed: {error}")
```

#### 4. HTTP Requests
```python
# In client.py
logger.info(f"Making token request to {redact_url(address)}")
logger.debug(f"Request payload: {redact_sensitive(payload)}")
logger.info(f"Token request successful, expires_in: {expires_in}")
logger.error(f"Token request failed: {status_code} - {error}")
```

### Implementation Tasks

1. **Create logging_config.py**: Logger setup and configuration
2. **Create logging_utils.py**: Redaction utilities
3. **Update all modules**: Add logging statements
4. **Add documentation**: Document logging configuration in docs
5. **Add tests**: Test logging output and redaction

### Example User Configuration
```python
# User's application
import logging
from py_identity_model.logging_config import configure_logging

# Enable debug logging for py-identity-model
configure_logging(level=logging.DEBUG)

# Or use standard Python logging
logging.basicConfig(level=logging.DEBUG)
```

---

## 5. Implementation Order

### Phase 1: Documentation Fixes (Immediate)
**Priority: HIGH** - Blocking CI/CD
1. Copy `CONTRIBUTING.md` to `docs/contributing.md`
2. Update `mkdocs.yml` navigation
3. Fix references in `faq.md` and `getting-started.md`
4. Verify with `mkdocs build --strict`

**Estimated Time**: 30 minutes

### Phase 2: Code Organization in identity.py (High Value, Low Risk)
**Priority: HIGH** - Improves code quality
1. Add `from __future__ import annotations` to `identity.py`
2. Reorder classes: `Claim`, `ClaimType`, `Identity`, `Principal`, `ClaimsIdentity`, `ClaimsPrincipal`
3. Remove all quoted type annotations (e.g., `"Claim"` → `Claim`)
4. Verify all tests still pass
5. Run type checking to ensure no issues

**Estimated Time**: 1 hour

### Phase 3: Exception Hierarchy (Foundation)
**Priority: MEDIUM** - Enables better error handling
1. Create `exceptions.py` with full hierarchy
2. Update imports in all modules
3. Replace generic exceptions with specific ones
4. Improve error messages with context
5. Add exception tests
6. Update documentation

**Estimated Time**: 4-6 hours

### Phase 4: Logger Integration (Enhancement)
**Priority: MEDIUM** - Improves debugging experience
1. Create `logging_config.py`
2. Create `logging_utils.py` with redaction
3. Add logging to discovery module
4. Add logging to JWKS module
5. Add logging to token validation
6. Add logging to client requests
7. Add logging documentation
8. Add logging tests

**Estimated Time**: 4-6 hours

---

## 6. Testing Strategy

### Identity Module Tests
```python
# tests/test_identity.py
def test_claims_identity_inherits_identity():
    """Verify ClaimsIdentity properly inherits from Identity ABC"""
    identity = ClaimsIdentity([], authentication_type="Bearer")
    assert isinstance(identity, Identity)
    assert identity.is_authenticated() == True

def test_abstract_instantiation_fails():
    """Verify abstract classes cannot be instantiated"""
    with pytest.raises(TypeError):
        Identity()  # Should fail - abstract class
```

### Exception Tests
```python
# tests/test_exceptions.py
def test_exception_hierarchy():
    """Verify exception inheritance"""
    assert issubclass(TokenValidationException, ValidationException)
    assert issubclass(ValidationException, PyIdentityModelException)

def test_exception_details():
    """Verify exception carries context"""
    ex = TokenValidationException(
        "Invalid signature",
        token_part="signature",
        details={"kid": "abc123"}
    )
    assert ex.token_part == "signature"
    assert ex.details["kid"] == "abc123"
```

### Logging Tests
```python
# tests/test_logging.py
def test_sensitive_data_redaction():
    """Verify sensitive data is redacted"""
    data = {
        "client_id": "my-client",
        "client_secret": "super-secret",
        "scope": "api:read"
    }
    redacted = redact_sensitive(data)
    assert redacted["client_secret"] == "***REDACTED***"
    assert redacted["client_id"] == "my-client"

def test_logging_output(caplog):
    """Verify logging produces expected output"""
    with caplog.at_level(logging.INFO):
        logger.info("Test message")
    assert "Test message" in caplog.text
```

---

## 7. Documentation Updates

### New Documentation Needed

1. **docs/logging.md** (new file)
   - How to configure logging
   - Logging levels and their purposes
   - Sensitive data handling
   - Example configurations

3. **docs/exceptions.md** (new file)
   - Exception hierarchy diagram
   - When each exception is raised
   - Exception handling examples
   - Best practices

4. **Update docs/contributing.md**
   - Add logging guidelines
   - Add exception handling guidelines
   - Add type checking with protocols

---

## 8. Breaking Changes Analysis

### Code Organization (identity.py)
**Breaking**: ❌ No
- Only internal file reorganization
- Public API remains unchanged
- All classes still exported the same way
- Type hints are cleaner but functionally equivalent

### Exception Hierarchy
**Breaking**: ⚠️ Potentially
- Old code catching `PyIdentityModelException` still works
- Code catching specific exceptions might break if we rename them
- **Mitigation**: Keep `PyIdentityModelException` as base, add new specific types

### Logging
**Breaking**: ❌ No
- Logging is opt-in
- Default `NullHandler` means no output unless configured
- No API changes

---

## 9. Success Criteria

### Documentation Fixes
- ✅ `mkdocs build --strict` completes without errors
- ✅ All internal links resolve correctly
- ✅ CONTRIBUTING.md accessible from docs

### Code Organization (identity.py)
- ✅ All tests pass
- ✅ Type checking passes
- ✅ No quoted type annotations remain
- ✅ Classes in logical dependency order
- ✅ No breaking changes to public API

### Exception Handling
- ✅ Comprehensive exception hierarchy in place
- ✅ All modules use specific exceptions
- ✅ Error messages include contextual information
- ✅ 100% test coverage for exceptions
- ✅ Exception documentation complete

### Logging
- ✅ Logging integrated in all major operations
- ✅ Sensitive data properly redacted
- ✅ Configurable logging levels
- ✅ No logging output by default
- ✅ Logging documentation complete
- ✅ Logging tests verify redaction

---

## 10. Risk Assessment

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| Class reordering breaks imports | Low | Low | All classes still exported, only internal order changes |
| Exception changes break error handling | Medium | Medium | Keep base exception, add deprecation warnings |
| Logging adds performance overhead | Low | Low | Use lazy evaluation, NullHandler by default |
| Documentation links break | Low | Low | Test build in strict mode before merge |

---

## 11. Rollout Plan

### Pre-merge Checklist
- [ ] All tests pass
- [ ] Type checking passes
- [ ] Documentation builds without warnings
- [ ] Code review completed
- [ ] CHANGELOG.md updated

### Post-merge Monitoring
- Monitor for issues in first week
- Update documentation based on user feedback
- Address any performance concerns with logging

---

## Summary

This implementation plan addresses all requested issues:

1. **Code Organization (identity.py)**: Eliminate forward references by reordering classes, keep ABC for strict enforcement
2. **MkDocs Fixes**: Resolve all broken links causing build failures
3. **Exception Handling**: Comprehensive hierarchy with contextual error information
4. **Logger Integration**: Production-grade logging with sensitive data protection

The plan prioritizes documentation fixes (blocking CI), followed by code organization improvements, then comprehensive exception handling and logging improvements. All changes maintain backward compatibility.

### Why ABC Over Protocol

The decision to keep ABC instead of migrating to Protocol is based on:
- **Strictness**: Runtime enforcement ensures correct implementation
- **Control**: We own all implementations in this library
- **Clarity**: Explicit inheritance makes the API contract clear
- **Philosophy**: Matches .NET IdentityModel design (strict contracts)
- **Library Design**: Better for libraries that enforce correct usage
