# py-identity-model Development Roadmap

## Project Overview
**Goal**: Production-grade Python OIDC/OAuth2.0 client library inspired by Duende.IdentityModel
**Current Status**: v2.17.2 — all core protocol features implemented, integration test infrastructure active
**Scope**: Client-side protocol operations (NOT server/provider implementation)

## Completed

### Core Infrastructure (v1.0–v1.2)
- Discovery Document (OpenID Connect Discovery 1.0)
- JWKS Retrieval (RFC 7517)
- JWT Validation with PyJWT integration
- Client Credentials Grant (RFC 6749)
- UserInfo Endpoint (OIDC Core)
- Async/Await API (`py_identity_model.aio`)
- Modular architecture (core/sync/aio separation)
- Thread-safe HTTP client management
- httpx migration with connection pooling

### Protocol Features (v2.9–v2.15)
- OAuth Callback State Validation
- Base Request/Response Classes
- HTTP Client Dependency Injection
- Enhanced Token Validation (custom validators, leeway, multi-audience)
- Authorization Code Grant + PKCE (RFC 7636)
- Refresh Token Grant (RFC 6749)
- Token Introspection (RFC 7662)
- Token Revocation (RFC 7009)
- Device Authorization Grant (RFC 8628)
- Token Exchange (RFC 8693)
- DPoP — Demonstrating Proof of Possession (RFC 9449)
- Pushed Authorization Requests (RFC 9126)
- JWT Secured Authorization Request (RFC 9101)
- FAPI 2.0 Security Profile Compliance
- Policy-Based Configuration (DiscoveryPolicy, DiscoveryEndpoint)

### Quality & Testing (v2.16–v2.17)
- Performance benchmarking tests
- node-oidc-provider Docker test fixture
- Provider-agnostic integration tests (discovery-driven capabilities)
- Ruff lint violations reduced (28 → 4 ignored rules)
- 67 weak tests removed, behavioral coverage maintained

---

## In Progress

### Integration Test Chain
- [x] T120: node-oidc-provider fixture (PR #274 merged)
- [ ] T121: Core flow integration tests (Auth Code+PKCE, Token Validation, Refresh) — PR #281 merged, CI follow-up active
- [ ] T122: Token management integration tests (Introspection, Revocation)
- [ ] T123: Advanced request pattern integration tests (DPoP, PAR, JAR)
- [ ] T124: Alternative grant integration tests (Device Auth, Token Exchange)
- [ ] T125: FAPI 2.0 integration tests
- [ ] T126: Duende IdentityServer gap analysis (PR #306 open)

---

## Planned

### Documentation & Examples
- [ ] Comprehensive API documentation ([#83](https://github.com/jamescrowley321/py-identity-model/issues/83))
- [ ] Provider examples: Auth0, Okta, Azure AD, Google, Cognito ([#35-#39](https://github.com/jamescrowley321/py-identity-model/issues/35))
- [ ] Flask middleware example ([#33](https://github.com/jamescrowley321/py-identity-model/issues/33))

### Extended Protocol Features
- [ ] Discovery Cache with configurable TTL ([#219](https://github.com/jamescrowley321/py-identity-model/issues/219))
- [ ] RP-Initiated Logout ([#214](https://github.com/jamescrowley321/py-identity-model/issues/214))
- [ ] JWT Client Authentication — private_key_jwt / client_secret_jwt ([#213](https://github.com/jamescrowley321/py-identity-model/issues/213))
- [ ] AS Issuer Identification — RFC 9207 ([#221](https://github.com/jamescrowley321/py-identity-model/issues/221))
- [ ] CIBA — Client-Initiated Backchannel Authentication ([#217](https://github.com/jamescrowley321/py-identity-model/issues/217))
- [ ] Rich Authorization Requests — RFC 9396 ([#220](https://github.com/jamescrowley321/py-identity-model/issues/220))
- [ ] Dynamic Client Registration — RFC 7591 ([#216](https://github.com/jamescrowley321/py-identity-model/issues/216))
- [ ] mTLS Client Auth — RFC 8705 ([#215](https://github.com/jamescrowley321/py-identity-model/issues/215))
- [ ] JARM — JWT Secured Authorization Response Mode ([#218](https://github.com/jamescrowley321/py-identity-model/issues/218))

### Cloud Provider Integration Testing
- [ ] AWS Cognito integration tests
- [ ] Microsoft Entra ID integration tests
- [ ] Auth0 integration tests
- [ ] Nightly CI for provider drift detection
