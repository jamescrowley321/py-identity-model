# Architecture Improvements Plan

This document outlines planned architectural improvements based on analysis of the [Duende IdentityModel C# library](https://github.com/DuendeSoftware/foss/tree/main/identity-model/src/IdentityModel).

## Current State

### Code Duplication Reduction (✅ Completed)
We've successfully extracted shared logic to reduce duplication between async/sync implementations:
- Created `core/discovery_logic.py` for shared discovery processing
- Created `core/jwks_logic.py` for shared JWKS processing
- Created `core/token_client_logic.py` for shared token client processing
- Reduced code duplication by ~30-41% across all implementations

### Remaining Gaps

While we've reduced duplication, we're missing several key abstractions from the C# library that would improve flexibility, testability, and maintainability.

---

## Missing Abstractions

### 1. DiscoveryPolicy - Security Configuration Object

#### What It Provides
A centralized, configurable security policy for discovery document validation with sensible defaults.

#### Key Features
- **HTTPS Enforcement**: Configurable requirement for HTTPS with development-friendly loopback exceptions
- **Authority Validation**: Validates issuer matches expected authority
- **Endpoint Validation**: Ensures all endpoints belong to the trusted authority
- **Exclusion Lists**: Allow-list for non-standard endpoints
- **Pluggable Strategies**: Strategy pattern for custom validation logic

#### Current State
- Validation logic scattered across `core/validators.py`
- No centralized policy configuration
- Hard-coded validation rules with no runtime customization

#### Proposed API
```python
from py_identity_model import DiscoveryPolicy

# Use defaults (strict security)
policy = DiscoveryPolicy(
    authority="https://demo.duendesoftware.com"
)

# Customize for development
dev_policy = DiscoveryPolicy(
    authority="http://localhost:5000",
    require_https=False,
    allow_http_on_loopback=True,
    loopback_addresses=["localhost", "127.0.0.1"]
)

# Disable specific validations
relaxed_policy = DiscoveryPolicy(
    authority="https://example.com",
    validate_issuer_name=False,
    validate_endpoints=True,
    endpoint_validation_exclude_list=["end_session_endpoint"]
)

# Use custom validation strategy
policy.authority_validation_strategy = CustomValidator()
```

#### Benefits
- **Security by Default**: Strict validation unless explicitly relaxed
- **Development Friendly**: Built-in support for local development
- **Testability**: Easy to test with different policies
- **Extensibility**: Custom validators via strategy pattern

---

### 2. DiscoveryEndpoint - URL Parsing & Authority Extraction

#### What It Provides
Intelligent parsing and validation of discovery endpoint URLs.

#### Key Features
- **Smart URL Parsing**: Detects if discovery path already included in URL
- **Authority Extraction**: Separates base authority from full discovery URL
- **Scheme Validation**: Validates HTTP/HTTPS with policy integration
- **Path Configuration**: Supports custom discovery paths (not just `.well-known/openid-configuration`)

#### Current State
- URLs passed as raw strings
- No separation of authority vs. discovery path
- Manual URL construction by users
- No validation until HTTP request

#### Proposed API
```python
from py_identity_model import DiscoveryEndpoint

# Parse full URL
endpoint = DiscoveryEndpoint.parse_url(
    "https://demo.duendesoftware.com/.well-known/openid-configuration"
)
# endpoint.authority = "https://demo.duendesoftware.com"
# endpoint.url = "https://demo.duendesoftware.com/.well-known/openid-configuration"

# Parse authority only (adds default path)
endpoint = DiscoveryEndpoint.parse_url("https://demo.duendesoftware.com")
# endpoint.url = "https://demo.duendesoftware.com/.well-known/openid-configuration"

# Custom discovery path
endpoint = DiscoveryEndpoint.parse_url(
    "https://custom-idp.com",
    path="/oauth/discovery"
)

# Validate against policy
if not DiscoveryEndpoint.is_secure_scheme(endpoint.url, policy):
    raise ValueError("HTTPS required")
```

#### Benefits
- **Consistency**: Standardized URL handling across library
- **Flexibility**: Support for non-standard discovery paths
- **Validation**: Early URL validation before network requests
- **Clarity**: Clear separation between authority and endpoints

---

### 3. Request Objects with Embedded Policy

#### What It Provides
Request objects that carry their own validation policy, enabling per-request customization.

#### Current State
```python
# Current: Only address property
request = DiscoveryDocumentRequest(address="https://example.com")
```

#### Proposed API
```python
from py_identity_model import DiscoveryDocumentRequest, DiscoveryPolicy

# Request with default policy
request = DiscoveryDocumentRequest(
    address="https://demo.duendesoftware.com"
)

# Request with custom policy
request = DiscoveryDocumentRequest(
    address="https://custom-idp.com",
    policy=DiscoveryPolicy(
        authority="https://custom-idp.com",
        validate_endpoints=False  # Relax validation for this request
    )
)

# Policy is used during response validation
response = await get_discovery_document(request)
```

#### Similar Pattern for Other Requests
```python
# JWKS request with policy
jwks_request = JwksRequest(
    address="https://demo.duendesoftware.com/jwks",
    policy=JwksPolicy(require_https=True)
)

# Token request with policy
token_request = ClientCredentialsTokenRequest(
    address="https://demo.duendesoftware.com/token",
    client_id="client",
    client_secret="secret",
    scope="api",
    policy=TokenPolicy(require_https=True)
)
```

#### Benefits
- **Per-Request Configuration**: Different policies for different requests
- **Testability**: Easy to test with various policy configurations
- **Clean Separation**: Request config separate from execution logic
- **Type Safety**: Policy validation at request construction time

---

### 4. Rich Response Objects with Validation Methods

#### What It Provides
Response objects with on-demand validation and helper methods for accessing data.

#### Current State
```python
# Current: Simple dataclass with properties
response = await get_discovery_document(request)
if response.is_successful:
    print(response.issuer)
    print(response.authorization_endpoint)
```

#### Proposed API
```python
from py_identity_model import DiscoveryDocumentResponse

response = await get_discovery_document(request)

if response.is_successful:
    # On-demand validation
    if not response.validate_issuer_name():
        print(f"Warning: Issuer mismatch - {response.error}")

    if not response.validate_endpoints():
        print(f"Warning: Invalid endpoints - {response.error}")

    # Helper methods for additional fields
    custom_endpoint = response.try_get_string("custom_endpoint")
    feature_enabled = response.try_get_boolean("feature_flag")
    supported_claims = response.try_get_string_array("claims_supported")

    # Automatic JWKS loading
    if response.key_set:
        # JWKS already fetched and populated
        for key in response.key_set.keys:
            print(f"Key ID: {key.kid}")
```

#### Benefits
- **Lazy Validation**: Validate only when needed
- **Error Details**: Clear error messages for validation failures
- **Extensibility**: Access custom/non-standard fields easily
- **Convenience**: Auto-loaded JWKS saves roundtrip

---

### 5. Strategy Pattern for Authority Validation

#### What It Provides
Pluggable validation strategies for authority/issuer validation.

#### Current State
- Hard-coded string comparison in validators
- No extension point for custom validation logic

#### Proposed API
```python
from abc import ABC, abstractmethod
from py_identity_model import (
    IAuthorityValidationStrategy,
    AuthorityValidationResult,
    DiscoveryPolicy
)

# Define custom strategy
class CustomAuthorityValidator(IAuthorityValidationStrategy):
    def validate(self, authority: str, issuer: str) -> AuthorityValidationResult:
        # Custom validation logic
        # Example: Accept multiple trusted issuers
        trusted_issuers = [
            "https://login.microsoftonline.com/tenant1",
            "https://login.microsoftonline.com/tenant2"
        ]

        if issuer in trusted_issuers:
            return AuthorityValidationResult(success=True)

        return AuthorityValidationResult(
            success=False,
            error=f"Issuer {issuer} not in trusted list"
        )

# Use custom validator
policy = DiscoveryPolicy(authority="https://login.microsoftonline.com")
policy.authority_validation_strategy = CustomAuthorityValidator()
```

#### Built-in Strategies
```python
# String comparison (default)
from py_identity_model import StringComparisonAuthorityValidationStrategy
policy.authority_validation_strategy = StringComparisonAuthorityValidationStrategy()

# URL-based validation (checks URL components)
from py_identity_model import AuthorityUrlValidationStrategy
policy.authority_validation_strategy = AuthorityUrlValidationStrategy()
```

#### Benefits
- **Extensibility**: Users can implement custom validation logic
- **Testability**: Easy to test with mock strategies
- **Flexibility**: Different strategies for different scenarios
- **Standards Compliance**: Can implement various OIDC validation approaches

---

### 6. Improved Project Structure

#### Current Structure
```
src/py_identity_model/
├── core/                    # Everything mixed together
│   ├── models.py
│   ├── validators.py
│   ├── parsers.py
│   ├── error_handlers.py
│   ├── response_processors.py
│   ├── discovery_logic.py
│   ├── jwks_logic.py
│   └── token_client_logic.py
├── aio/                     # Async implementations
│   ├── discovery.py
│   ├── jwks.py
│   └── token_client.py
├── sync/                    # Sync implementations
│   ├── discovery.py
│   ├── jwks.py
│   └── token_client.py
└── (various other files)
```

#### Proposed Structure
```
src/py_identity_model/
├── client/                  # Client operations
│   ├── messages/           # Request/Response DTOs
│   │   ├── discovery_request.py
│   │   ├── discovery_response.py
│   │   ├── jwks_request.py
│   │   ├── jwks_response.py
│   │   └── token_request.py
│   ├── policies/           # Policy objects
│   │   ├── discovery_policy.py
│   │   ├── jwks_policy.py
│   │   └── token_policy.py
│   ├── endpoints/          # Endpoint handling
│   │   ├── discovery_endpoint.py
│   │   └── token_endpoint.py
│   ├── aio/               # Async client implementations
│   │   ├── discovery.py
│   │   ├── jwks.py
│   │   └── token_client.py
│   └── sync/              # Sync client implementations
│       ├── discovery.py
│       ├── jwks.py
│       └── token_client.py
├── validation/             # Validation logic
│   ├── strategies/        # Validation strategies
│   │   ├── authority_validation_strategy.py
│   │   └── endpoint_validation_strategy.py
│   ├── validators.py
│   └── compliance.py
├── jwk/                   # JSON Web Key handling
│   ├── json_web_key.py
│   ├── parsers.py
│   └── key_set.py
├── core/                  # Core abstractions
│   ├── constants.py       # OIDC constants
│   ├── claim_types.py     # JWT claim types
│   └── models.py          # Core models
└── (identity, http_client, etc.)
```

#### Benefits
- **Clarity**: Clear separation of concerns
- **Discoverability**: Easier to find relevant code
- **Maintainability**: Related code grouped together
- **Scalability**: Easier to add new features

---

### 7. Automatic JWKS Loading

#### What It Provides
Discovery responses automatically fetch and populate the JWKS from `jwks_uri`.

#### Current State
```python
# Current: Two-step process
disco = await get_discovery_document(request)
if disco.is_successful and disco.jwks_uri:
    jwks = await get_jwks(JwksRequest(address=disco.jwks_uri))
    # Now have both disco and jwks
```

#### Proposed API
```python
# Proposed: Automatic loading
disco = await get_discovery_document(request)
if disco.is_successful:
    # key_set already populated
    if disco.key_set:
        for key in disco.key_set.keys:
            print(f"Using key: {key.kid}")

# Optional: Disable auto-loading
request = DiscoveryDocumentRequest(
    address="https://demo.duendesoftware.com",
    load_jwks=False  # Skip automatic JWKS fetch
)
```

#### Benefits
- **Convenience**: One call gets everything needed for validation
- **Performance**: Can be done in parallel with discovery fetch
- **Simplicity**: Fewer steps for common use case
- **Flexibility**: Can disable for special cases

---

## Implementation Priority

### Phase 1: Foundation (High Impact)
1. **DiscoveryPolicy** - Enables configuration and testing
2. **DiscoveryEndpoint** - Proper URL handling
3. **Request objects with policy** - Better API design

### Phase 2: Enhancement (Medium Impact)
4. **Validation methods on response** - On-demand validation
5. **Strategy pattern for validators** - Extensibility
6. **Automatic JWKS loading** - Better UX

### Phase 3: Restructuring (Lower Risk)
7. **Improved project structure** - Better organization

---

## Migration Strategy

### Backward Compatibility

All changes should maintain backward compatibility for at least one major version:

```python
# Old API (deprecated but still works)
request = DiscoveryDocumentRequest(address="https://example.com")

# New API (recommended)
request = DiscoveryDocumentRequest(
    address="https://example.com",
    policy=DiscoveryPolicy(authority="https://example.com")
)
```

### Deprecation Warnings
```python
import warnings

def get_discovery_document(disco_doc_req):
    if not hasattr(disco_doc_req, 'policy'):
        warnings.warn(
            "DiscoveryDocumentRequest without policy is deprecated. "
            "Please use DiscoveryPolicy for configuration.",
            DeprecationWarning,
            stacklevel=2
        )
```

---

## Testing Strategy

### Unit Tests
- Test each policy configuration
- Test all validation strategies
- Test URL parsing edge cases
- Test backward compatibility

### Integration Tests
- Test with real OIDC providers
- Test policy enforcement
- Test automatic JWKS loading
- Test error scenarios

### Performance Tests
- Benchmark validation overhead
- Measure impact of automatic JWKS loading
- Compare with current implementation

---

## Documentation Requirements

### User Guide
- Migration guide from old to new API
- Policy configuration examples
- Custom validator examples
- Best practices for each use case

### API Reference
- Complete policy option documentation
- Validation strategy interface
- Request/response object reference

### Examples
- Basic usage with defaults
- Development configuration
- Production configuration
- Custom validation scenarios

---

## Success Criteria

1. **Flexibility**: Users can configure validation per-request
2. **Security**: Secure defaults, explicit opt-out for relaxed security
3. **Compatibility**: No breaking changes to existing API
4. **Performance**: No significant performance degradation
5. **Maintainability**: Code is better organized and testable
6. **Documentation**: Clear migration path and examples

---

## References

- [Duende IdentityModel (C#)](https://github.com/DuendeSoftware/foss/tree/main/identity-model/src/IdentityModel)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [RFC 8414 - OAuth 2.0 Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414.html)
