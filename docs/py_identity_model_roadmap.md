# py-identity-model Development Roadmap

## Project Overview
**Goal**: Create a Python port of Duende.IdentityModel - a client library for interacting with OAuth 2.0 and OpenID Connect endpoints

**Current Status**: Production-ready library with core features implemented (v2.1.0)

**Scope**: Client-side protocol operations (NOT server/provider implementation)

## ✅ Currently Implemented Features
- ✅ **Discovery Document**: `DiscoveryDocumentRequest`, `get_discovery_document()` - **Implements OpenID Connect Discovery 1.0**
- ✅ **JWKS Retrieval**: `JwksRequest`, `get_jwks()` - **Implements RFC 7517**
- ✅ **JWT Validation**: `TokenValidationConfig`, `validate_token()` with PyJWT integration
- ✅ **Client Credentials Flow**: `ClientCredentialsTokenRequest`, `request_client_credentials_token()`
- ✅ **UserInfo Endpoint**: `UserInfoRequest`, `get_userinfo()` - OpenID Connect Core 1.0 Section 5.3 (v2.1.0)
- ✅ **Token-to-Principal Conversion**: `to_principal()` - Converts JWTs to `ClaimsPrincipal` objects
- ✅ **Protocol Constants**: OIDC and OAuth 2.0 constants (`OidcConstants`, `JwtClaimTypes`)
- ✅ **Exception Handling**: `PyIdentityModelException` with structured exception hierarchy
- ✅ **Comprehensive Type Hints**: Full type safety throughout the codebase
- ✅ **Async/Await Support**: Full async API via `py_identity_model.aio` module (v1.2.0)
- ✅ **HTTP Client**: httpx-based client supporting both sync and async operations with retry logic
- ✅ **Testing Infrastructure**: 259 tests (unit + integration) with 95%+ coverage
- ✅ **Production Usage**: Used in production Flask/FastAPI middleware for years
- ✅ **CI/CD Pipeline**: GitHub Actions with semantic-release, SonarCloud integration
- ✅ **Published on PyPI**: Proper versioning with semantic-release automation

---

## Phase 1: Foundation & Quality ✅ **COMPLETED**
### Core Infrastructure
- [x] **Testing & Quality Enhancement**
  - ✅ Test suite with 259 tests (unit + integration)
  - ✅ Integration tests against Ory and Duende IdentityServer
  - ✅ Coverage reporting with 95%+ coverage (SonarCloud + pytest-cov)
  - [ ] Add performance benchmarking tests ([#112](https://github.com/jamescrowley321/py-identity-model/issues/112))
  - [ ] Integration tests for Descope provider ([#158](https://github.com/jamescrowley321/py-identity-model/issues/158))

- [x] **Documentation & Packaging**
  - ✅ README with comprehensive usage examples
  - ✅ Python packaging with `pyproject.toml` and `uv` build system
  - ✅ Published to PyPI with semantic-release automation
  - ✅ Complete type hints throughout
  - [ ] Comprehensive API reference documentation ([#83](https://github.com/jamescrowley321/py-identity-model/issues/83))

- [x] **Code Structure Improvements**
  - ✅ Proper package structure in `src/py_identity_model/`
  - ✅ Structured exception hierarchy (`PyIdentityModelException` base)
  - ✅ Logging infrastructure (`logging_config.py`, `logging_utils.py`)
  - [ ] Base classes for requests/responses ([#88](https://github.com/jamescrowley321/py-identity-model/issues/88))

### Deliverables
- ✅ Package structure and functionality
- ✅ Test infrastructure in place
- ✅ Published PyPI package with proper versioning
- ✅ CI/CD pipeline (GitHub Actions)
- [ ] Performance benchmarking ([#112](https://github.com/jamescrowley321/py-identity-model/issues/112))

---

## Phase 2: Core Protocol Support
### Token Endpoint Operations
- [ ] **Expand Token Endpoint Support**
  - ✅ Client credentials grant (completed)
  - [ ] Authorization code grant type with PKCE ([#90](https://github.com/jamescrowley321/py-identity-model/issues/90))
  - [ ] Refresh token grant type ([#19](https://github.com/jamescrowley321/py-identity-model/issues/19))
  - [ ] Device authorization grant type ([#91](https://github.com/jamescrowley321/py-identity-model/issues/91))
  - [ ] Token exchange (RFC 8693) ([#92](https://github.com/jamescrowley321/py-identity-model/issues/92))

- [ ] **Request/Response Models Enhancement**
  - ✅ Basic `TokenRequest` classes (ClientCredentialsTokenRequest)
  - [ ] `TokenRequest` base class with specific implementations ([#88](https://github.com/jamescrowley321/py-identity-model/issues/88))
  - [ ] `TokenResponse` with proper error handling
  - [ ] Support for all standard OAuth parameters
  - [ ] Custom parameter support

- [ ] **Token Validation Enhancement** ([#93](https://github.com/jamescrowley321/py-identity-model/issues/93))
  - ✅ JWT validation with PyJWT integration
  - ✅ Discovery document integration for validation
  - ✅ Custom claims validation (sync and async validators)
  - [ ] Support for multiple issuers
  - [ ] JWE (encrypted JWT) support
  - [ ] Token binding validation
  - [ ] OAuth callback state validation ([#116](https://github.com/jamescrowley321/py-identity-model/issues/116))

### Deliverables
- ✅ Client credentials token endpoint (completed)
- ✅ JWT validation with custom claims (completed)
- [ ] Complete token endpoint client for all grant types
- [ ] Enhanced JWT validation features

---

## Phase 3: Discovery & Metadata ✅ **COMPLETED**
### Discovery Document Enhancement
- [x] **Extended Discovery Support**
  - ✅ OpenID Connect discovery document parsing - **Implements OpenID Connect Discovery 1.0**
  - ✅ JWKS endpoint discovery and retrieval - **Implements RFC 7517**
  - ✅ OAuth 2.0 Authorization Server Metadata (RFC 8414)
  - ✅ Full parameter validation and error handling
  - ✅ Issuer format validation
  - ✅ Endpoint URL validation
  - ✅ Caching with `functools.lru_cache` (sync) and `async_lru.alru_cache` (async)
  - ✅ Retry logic with exponential backoff

- [ ] **Endpoint Clients**
  - [ ] Authorization endpoint URL builder
  - [ ] End session endpoint support
  - [ ] Check session iframe support

- [x] **Constants & Helpers**
  - ✅ `OidcConstants` - OpenID Connect constants (scopes, claims, parameters)
  - ✅ `JwtClaimTypes` - Standard JWT claim type names
  - ✅ Validation utilities (`core/validators.py`)
  - ✅ Response parsing utilities (`core/parsers.py`, `core/response_processors.py`)

### Deliverables
- ✅ **Discovery document support** - Implements OpenID Connect Discovery 1.0
- ✅ **JWKS retrieval** - Implements RFC 7517
- ✅ Comprehensive parameter validation and error handling
- ✅ Constants library (`OidcConstants`, `JwtClaimTypes`)
- [ ] All standard endpoint clients

---

## Phase 4: Advanced Features
### Advanced Protocol Support
- [ ] **Token Introspection (RFC 7662)** ([#16](https://github.com/jamescrowley321/py-identity-model/issues/16))
  - `TokenIntrospectionRequest/Response` classes
  - Support for different token types
  - Introspection endpoint client

- [ ] **Token Revocation (RFC 7009)** ([#17](https://github.com/jamescrowley321/py-identity-model/issues/17))
  - `TokenRevocationRequest` class
  - Support for access_token and refresh_token revocation
  - Revocation endpoint client

- [x] **UserInfo Endpoint** - ✅ **COMPLETED v2.1.0**
  - ✅ `UserInfoRequest/Response` classes
  - ✅ Claims parsing and validation
  - ✅ UserInfo endpoint client (sync and async)

- [ ] **Dynamic Client Registration (RFC 7591)**
  - `ClientRegistrationRequest/Response` classes
  - Client metadata management
  - Registration endpoint client

### Deliverables
- [ ] Token introspection support ([#16](https://github.com/jamescrowley321/py-identity-model/issues/16))
- [ ] Token revocation support ([#17](https://github.com/jamescrowley321/py-identity-model/issues/17))
- ✅ UserInfo endpoint client
- [ ] Dynamic client registration

---

## Phase 5: Modern Features & Security
### Security & Modern Standards
- [ ] **DPoP (RFC 9449) Support** ([#94](https://github.com/jamescrowley321/py-identity-model/issues/94))
  - DPoP proof creation
  - DPoP token binding
  - Integration with token requests

- [ ] **Pushed Authorization Requests (RFC 9126)** ([#95](https://github.com/jamescrowley321/py-identity-model/issues/95))
  - PAR request/response handling
  - Integration with authorization flows
  - Enhanced security validation

- [ ] **JWT Secured Authorization Request (RFC 9101)** ([#96](https://github.com/jamescrowley321/py-identity-model/issues/96))
  - Request object creation
  - JWT request parameter support
  - Request URI handling

- [ ] **FAPI Security Profile Support** ([#97](https://github.com/jamescrowley321/py-identity-model/issues/97))
  - FAPI 2.0 compliance helpers
  - Enhanced security validations
  - MTLS support preparation

### Deliverables
- [ ] DPoP implementation ([#94](https://github.com/jamescrowley321/py-identity-model/issues/94))
- [ ] PAR support ([#95](https://github.com/jamescrowley321/py-identity-model/issues/95))
- [ ] JAR support ([#96](https://github.com/jamescrowley321/py-identity-model/issues/96))
- [ ] FAPI compliance helpers ([#97](https://github.com/jamescrowley321/py-identity-model/issues/97))

---

## Phase 6: Integration & Polish
### Framework Integration & Utilities
- [x] **HTTP Client Abstraction** - ✅ **COMPLETED v1.2.0**
  - ✅ Migrated to httpx for both sync and async (replaced requests)
  - ✅ Configurable timeouts (30s default on all HTTP calls)
  - ✅ Connection pooling via httpx (automatic)
  - ✅ Custom headers support via httpx Client
  - ✅ Retry logic with exponential backoff for rate limiting
  - [ ] Dependency injection support for HTTP client ([#117](https://github.com/jamescrowley321/py-identity-model/issues/117))

- [x] **Async Support** - ✅ **COMPLETED v1.2.0**
  - ✅ Async versions of all client methods (`py_identity_model.aio` module)
  - ✅ Async-compatible response models (shared dataclasses)
  - ✅ Performance optimization for async workflows with httpx.AsyncClient
  - ✅ Async caching with `async-lru` for discovery and JWKS
  - ✅ Full backward compatibility maintained (sync API unchanged)

- [x] **Modular Architecture** - ✅ **COMPLETED v1.2.0**
  - ✅ Extracted shared business logic to `core/` module
  - ✅ Eliminated code duplication between sync/async implementations
  - ✅ Clean separation: HTTP layer (sync/aio) vs business logic (core)
  - ✅ Reduced codebase size by eliminating duplication

- [x] **Integration Helpers** - Partially completed
  - ✅ FastAPI middleware example with token validation (`examples/fastapi/middleware.py`)
  - ✅ FastAPI dependency injection utilities (`examples/fastapi/dependencies.py`)
  - ✅ FastAPI full application example (`examples/fastapi/app.py`)
  - ✅ Token refresh pattern (`examples/fastapi/token_refresh.py`)
  - [ ] Flask middleware example ([#33](https://github.com/jamescrowley321/py-identity-model/issues/33))
  - [ ] Provider-specific examples: Azure AD ([#35](https://github.com/jamescrowley321/py-identity-model/issues/35)), Google ([#36](https://github.com/jamescrowley321/py-identity-model/issues/36)), Cognito ([#37](https://github.com/jamescrowley321/py-identity-model/issues/37)), Auth0 ([#38](https://github.com/jamescrowley321/py-identity-model/issues/38)), Okta ([#39](https://github.com/jamescrowley321/py-identity-model/issues/39))
  - [ ] Descope FastAPI example ([#159](https://github.com/jamescrowley321/py-identity-model/issues/159))

### Deliverables
- ✅ Full async support
- ✅ FastAPI integration examples
- ✅ Production-ready release (v2.1.0)
- [ ] Flask integration example ([#33](https://github.com/jamescrowley321/py-identity-model/issues/33))
- [ ] Provider-specific examples

---

## Phase 7: Code Quality & Refactoring ✅ **COMPLETED v1.2.0**
### Eliminate Code Duplication
- [x] **Extract Common Abstractions** - ✅ **COMPLETED**
  - ✅ Create `core/` module for shared business logic
  - ✅ Move shared dataclasses to `core/models.py`
  - ✅ Extract validation functions to `core/validators.py`
  - ✅ Extract parsing logic to `core/parsers.py`
  - ✅ Create `core/jwt_helpers.py` for JWT operations
  - ✅ Extract shared logic: `discovery_logic.py`, `jwks_logic.py`, `token_client_logic.py`, `userinfo_logic.py`

- [x] **Refactor HTTP Layers** - ✅ **COMPLETED**
  - ✅ Simplify `sync/` modules to focus on HTTP operations only
  - ✅ Simplify `aio/` modules to mirror sync structure
  - ✅ Ensure both call shared validators and parsers from `core/`

- [x] **Test Coverage** - ✅ **COMPLETED**
  - ✅ 259 tests passing with 95%+ coverage
  - ✅ Async/sync equivalence tests
  - ✅ Thread safety tests
  - ✅ Zero regressions in integration tests
  - [ ] Target ≥90% unit test coverage ([#111](https://github.com/jamescrowley321/py-identity-model/issues/111))

### Deliverables
- ✅ Reduced code duplication between sync/async implementations
- ✅ Cleaner separation between HTTP layer and business logic
- ✅ Improved maintainability and testability
- ✅ Comprehensive test suite

---

## Phase 8: Architecture Improvements - **PLANNED v2.0.0**
> **See [Issue #109](https://github.com/jamescrowley321/py-identity-model/issues/109)**

### Policy-Based Configuration (v2.0.0)
- [ ] **DiscoveryPolicy** - Security configuration object
  - Centralized, configurable security policy
  - HTTPS enforcement with loopback exceptions for development
  - Pluggable validation strategies (Strategy pattern)
  - Configurable authority and endpoint validation

- [ ] **DiscoveryEndpoint** - URL parsing & authority extraction
  - Intelligent URL parsing (detects discovery path)
  - Separates authority from full discovery URL
  - Smart detection of custom discovery paths
  - Scheme validation integrated with policy

- [ ] **Request Objects with Embedded Policy**
  - Requests carry their own validation policy
  - Per-request policy customization
  - Clean separation between request config and execution
  - Backward compatible (policy optional)

### Enhanced Response Objects (v2.1.0)
- [ ] **Rich Response Validation**
  - On-demand validation methods (`validate_issuer_name()`, `validate_endpoints()`)
  - Helper methods for custom fields (`try_get_string()`, `try_get_boolean()`)
  - Automatic JWKS loading from `jwks_uri` (with opt-out)
  - Lazy validation for better performance

- [ ] **Validation Strategy Pattern**
  - `IAuthorityValidationStrategy` interface
  - Built-in strategies (string comparison, URL-based)
  - User-implementable custom validators
  - Easy testing with mock strategies

### Deliverables
- [ ] Policy-based security configuration (v2.0.0)
- [ ] Enhanced validation and response handling (v2.1.0)
- [ ] Complete migration guide and examples
- [ ] Maintain backward compatibility throughout

---

## Open Issues by Category

### Protocol Features
| Issue | Feature | Status |
|-------|---------|--------|
| [#16](https://github.com/jamescrowley321/py-identity-model/issues/16) | Token Introspection (RFC 7662) | Phase 4 |
| [#17](https://github.com/jamescrowley321/py-identity-model/issues/17) | Token Revocation (RFC 7009) | Phase 4 |
| [#19](https://github.com/jamescrowley321/py-identity-model/issues/19) | Refresh Token Grant | Phase 2 |
| [#90](https://github.com/jamescrowley321/py-identity-model/issues/90) | Authorization Code + PKCE | Phase 2 |
| [#91](https://github.com/jamescrowley321/py-identity-model/issues/91) | Device Authorization (RFC 8628) | Phase 2 |
| [#92](https://github.com/jamescrowley321/py-identity-model/issues/92) | Token Exchange (RFC 8693) | Phase 2 |
| [#93](https://github.com/jamescrowley321/py-identity-model/issues/93) | Enhanced Token Validation | Phase 2 |
| [#94](https://github.com/jamescrowley321/py-identity-model/issues/94) | DPoP (RFC 9449) | Phase 5 |
| [#95](https://github.com/jamescrowley321/py-identity-model/issues/95) | PAR (RFC 9126) | Phase 5 |
| [#96](https://github.com/jamescrowley321/py-identity-model/issues/96) | JAR (RFC 9101) | Phase 5 |
| [#97](https://github.com/jamescrowley321/py-identity-model/issues/97) | FAPI 2.0 Security Profile | Phase 5 |
| [#116](https://github.com/jamescrowley321/py-identity-model/issues/116) | OAuth Callback State Validation | Phase 2 |

### Architecture & Quality
| Issue | Feature | Status |
|-------|---------|--------|
| [#88](https://github.com/jamescrowley321/py-identity-model/issues/88) | Base Request/Response Classes | Phase 2 |
| [#109](https://github.com/jamescrowley321/py-identity-model/issues/109) | Policy-Based Configuration | Phase 8 |
| [#110](https://github.com/jamescrowley321/py-identity-model/issues/110) | SonarCloud Quality Issues | Maintenance |
| [#111](https://github.com/jamescrowley321/py-identity-model/issues/111) | 90% Test Coverage Target | Phase 7 |
| [#112](https://github.com/jamescrowley321/py-identity-model/issues/112) | Performance Benchmarking | Phase 1 |
| [#113](https://github.com/jamescrowley321/py-identity-model/issues/113) | Optional Error Fields (Type Safety) | Maintenance |
| [#117](https://github.com/jamescrowley321/py-identity-model/issues/117) | DI Support for HTTP Client | Phase 6 |

### Documentation & Examples
| Issue | Feature | Status |
|-------|---------|--------|
| [#33](https://github.com/jamescrowley321/py-identity-model/issues/33) | Flask Middleware Example | Phase 6 |
| [#35](https://github.com/jamescrowley321/py-identity-model/issues/35) | Azure AD Example | Phase 6 |
| [#36](https://github.com/jamescrowley321/py-identity-model/issues/36) | Google Example | Phase 6 |
| [#37](https://github.com/jamescrowley321/py-identity-model/issues/37) | Cognito Example | Phase 6 |
| [#38](https://github.com/jamescrowley321/py-identity-model/issues/38) | Auth0 Example | Phase 6 |
| [#39](https://github.com/jamescrowley321/py-identity-model/issues/39) | Okta Example | Phase 6 |
| [#83](https://github.com/jamescrowley321/py-identity-model/issues/83) | Comprehensive API Docs | Phase 1 |
| [#158](https://github.com/jamescrowley321/py-identity-model/issues/158) | Descope Integration Tests | Testing |
| [#159](https://github.com/jamescrowley321/py-identity-model/issues/159) | Descope FastAPI Example | Phase 6 |

---

## Complete C# to Python Porting Checklist

### Core Client Messages (src/Client/Messages/)
- [x] **ClientCredentialsTokenRequest.cs** - ✅ Implemented as `ClientCredentialsTokenRequest`
- [x] **UserInfoRequest.cs** - ✅ Implemented as `UserInfoRequest`
- [x] **UserInfoResponse.cs** - ✅ Implemented as `UserInfoResponse`
- [x] **DiscoveryDocumentRequest.cs** - ✅ Implemented
- [x] **DiscoveryDocumentResponse.cs** - ✅ Implemented
- [x] **JwksRequest.cs** - ✅ Implemented
- [x] **JwksResponse.cs** - ✅ Implemented
- [ ] **TokenResponse.cs** - Base token response handling
- [ ] **TokenRequest.cs** - Base token request handling ([#88](https://github.com/jamescrowley321/py-identity-model/issues/88))
- [ ] **AuthorizationCodeTokenRequest.cs** - Authorization code flow ([#90](https://github.com/jamescrowley321/py-identity-model/issues/90))
- [ ] **RefreshTokenRequest.cs** - Refresh token flow ([#19](https://github.com/jamescrowley321/py-identity-model/issues/19))
- [ ] **DeviceTokenRequest.cs** - Device authorization flow ([#91](https://github.com/jamescrowley321/py-identity-model/issues/91))
- [ ] **TokenExchangeRequest.cs** - Token exchange (RFC 8693) ([#92](https://github.com/jamescrowley321/py-identity-model/issues/92))
- [ ] **IntrospectionRequest.cs** - Token introspection requests ([#16](https://github.com/jamescrowley321/py-identity-model/issues/16))
- [ ] **IntrospectionResponse.cs** - Token introspection responses ([#16](https://github.com/jamescrowley321/py-identity-model/issues/16))
- [ ] **RevocationRequest.cs** - Token revocation requests ([#17](https://github.com/jamescrowley321/py-identity-model/issues/17))
- [ ] **DeviceAuthorizationRequest.cs** - Device authorization requests ([#91](https://github.com/jamescrowley321/py-identity-model/issues/91))
- [ ] **DeviceAuthorizationResponse.cs** - Device authorization responses ([#91](https://github.com/jamescrowley321/py-identity-model/issues/91))
- [ ] **ClientRegistrationRequest.cs** - Dynamic client registration
- [ ] **ClientRegistrationResponse.cs** - Dynamic client registration responses
- [ ] **PushedAuthorizationRequest.cs** - PAR requests (RFC 9126) ([#95](https://github.com/jamescrowley321/py-identity-model/issues/95))
- [ ] **PushedAuthorizationResponse.cs** - PAR responses (RFC 9126) ([#95](https://github.com/jamescrowley321/py-identity-model/issues/95))

### Constants (src/Constants/)
- [x] **OidcConstants.cs** - ✅ Implemented as `OidcConstants`
- [x] **JwtClaimTypes.cs** - ✅ Implemented as `JwtClaimTypes`
- [ ] **OAuth2Constants.cs** - OAuth 2.0 constants
- [ ] **JwtHeaderParameterNames.cs** - JWT header parameter names
- [ ] **ProtocolRoutePaths.cs** - Standard protocol route paths

### JWT Handling (src/Jwt/)
- [x] **JsonWebKey.cs** - ✅ Implemented
- [x] **JsonWebKeySet.cs** - ✅ Implemented
- [x] **JwtTokenValidation.cs** - ✅ Implemented as `validate_token()`
- [ ] **JwtPayload.cs** - JWT payload handling
- [ ] **JwtHeader.cs** - JWT header handling
- [ ] **JwtSecurityToken.cs** - JWT token representation

### HTTP Client Abstractions (src/Client/)
- [x] **HttpClientDiscoveryExtensions.cs** - ✅ Implemented as `get_discovery_document()`
- [x] **HttpClientJwksExtensions.cs** - ✅ Implemented as `get_jwks()`
- [x] **HttpClientUserInfoExtensions.cs** - ✅ Implemented as `get_userinfo()`
- [ ] **HttpClientTokenRequestExtensions.cs** - Token request extensions
- [ ] **HttpClientIntrospectionExtensions.cs** - Introspection extensions ([#16](https://github.com/jamescrowley321/py-identity-model/issues/16))
- [ ] **HttpClientRevocationExtensions.cs** - Revocation extensions ([#17](https://github.com/jamescrowley321/py-identity-model/issues/17))
- [ ] **HttpClientDeviceExtensions.cs** - Device flow extensions ([#91](https://github.com/jamescrowley321/py-identity-model/issues/91))
- [ ] **HttpClientRegistrationExtensions.cs** - Client registration extensions

### Error Handling (src/Exceptions/)
- [x] **ProtocolException.cs** - ✅ Implemented as `PyIdentityModelException`
- [ ] **HttpRequestException.cs** - HTTP-specific exceptions
- [ ] **ValidationException.cs** - Token validation exceptions

### Models (src/Models/)
- [x] **TokenValidationParameters.cs** - ✅ Implemented as `TokenValidationConfig`
- [x] **ClaimsPrincipal.cs** - ✅ Implemented as `ClaimsPrincipal` with `to_principal()`
- [ ] **IdentityModel.cs** - Core identity model classes
- [ ] **SecurityToken.cs** - Security token base class

### Not Yet Started
- [ ] Protocol Extensions (src/Extensions/) - HTTP client, dictionary, string, response extensions
- [ ] Utilities (src/Utilities/) - Base64Url, Epoch, CryptoRandom, hashing
- [ ] Authorization Request Building (src/AuthorizeRequest/)
- [ ] PKCE Support (src/Pkce/) ([#90](https://github.com/jamescrowley321/py-identity-model/issues/90))
- [ ] DPoP Support (src/DPoP/) ([#94](https://github.com/jamescrowley321/py-identity-model/issues/94))
- [ ] Configuration (src/Configuration/) - Logging, options, HTTP client config

---

## Success Metrics
- **Feature Parity**: 80%+ of Duende.IdentityModel features (currently ~40%)
- **Code Quality**: ✅ Full type hints, 259 tests passing, 95%+ coverage
  - ✅ Code duplication reduced by 30-41% (Phase 7 complete)
  - 📋 **Next**: Architecture improvements with policy-based configuration (Phase 8)
- **Async/Await**: ✅ Complete (v1.2.0) - Both sync and async APIs available
- **Performance**: <50ms for typical operations (with caching: <1ms)
- **Adoption**: Active development, production usage in Flask/FastAPI middleware
- **Standards Implementation**:
  - ✅ Implements OpenID Connect Discovery 1.0 (not yet officially certified)
  - ✅ Implements RFC 7517 (JWKS) (not yet officially certified)
- **Architecture**: 📋 Phase 8 planned for v2.0 - Policy-based configuration and enhanced abstractions ([Issue #109](https://github.com/jamescrowley321/py-identity-model/issues/109))

## Technical Priorities
1. **Correctness**: Strict adherence to OAuth/OIDC specifications
2. **Security**: Secure defaults, proper validation
3. **Usability**: Pythonic API design, clear documentation
4. **Performance**: Efficient HTTP handling, caching
5. **Compatibility**: Python 3.12+ with comprehensive type hints

---

*This roadmap focuses on building a comprehensive OAuth/OIDC client library that mirrors the functionality and design patterns of Duende.IdentityModel while being idiomatic Python.*
