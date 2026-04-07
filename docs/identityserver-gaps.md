# Duende IdentityServer vs node-oidc-provider: Test Fixture Gap Analysis

This document compares the two OIDC test fixtures used by py-identity-model and recommends a path forward.

## Background

py-identity-model historically used a Duende IdentityServer (.NET) fixture for integration testing (`examples/identity-server/`). As the library expanded to cover advanced OAuth 2.0/OIDC specifications (DPoP, PAR, JAR, Device Authorization, Token Exchange, FAPI 2.0), a node-oidc-provider fixture was added (`test-fixtures/node-oidc-provider/`) to provide coverage that IdentityServer cannot.

## Feature Comparison

| Feature / RFC | IdentityServer | node-oidc-provider | Notes |
|---|:---:|:---:|---|
| **Core Protocol** | | | |
| OpenID Connect Discovery 1.0 | Yes | Yes | Both expose `/.well-known/openid-configuration` |
| JWKS (RFC 7517) | Yes | Yes | node: RSA + EC keys with explicit KIDs; IS: implicit single key |
| Client Credentials (RFC 6749) | Yes | Yes | |
| Authorization Code + PKCE (RFC 7636) | Partial | Yes | IS: auth code client configured but no PKCE enforcement; node: dedicated public PKCE client |
| Refresh Tokens | Yes | Yes | IS: via `offline_access`; node: same |
| **Token Management** | | | |
| Token Introspection (RFC 7662) | No | Yes | Not enabled in IS fixture |
| Token Revocation (RFC 7009) | No | Yes | Not enabled in IS fixture |
| **Advanced Request Mechanisms** | | | |
| DPoP (RFC 9449) | No | Yes | Not supported by Duende in test config |
| Pushed Authorization Requests (RFC 9126) | No | Yes | |
| JWT-Secured Authorization Requests (RFC 9101) | No | Yes | |
| **Alternative Grant Types** | | | |
| Device Authorization (RFC 8628) | No | Yes | Custom UI handler in node fixture |
| Token Exchange (RFC 8693) | No | Yes | Custom grant handler in node fixture |
| **Security Profiles** | | | |
| FAPI 2.0 Security Profile | No | Planned (T125) | Requires `private_key_jwt`, signed request objects, PAR enforcement |
| Resource Indicators (RFC 8707) | No | Yes | node uses this for JWT vs opaque token selection |
| **Test Infrastructure** | | | |
| Custom JWT claims (`dct`, `tenants`) | No | Yes | Descope-style multi-tenant claims via `extraTokenClaims` |
| Multiple signing algorithms | No | Yes | node: RS256 + ES256; IS: default algorithm only |
| Opaque token support | No | Yes | node: dedicated `test-opaque` client for introspection/revocation tests |
| Public client (no secret) | No | Yes | node: `test-pkce-public` client |

**Summary:** IdentityServer covers 4 of 14 features. node-oidc-provider covers 13 of 14 (FAPI 2.0 planned).

## Client Configuration Comparison

### IdentityServer (2 clients)

| Client ID | Grant Types | Scopes |
|---|---|---|
| `py-identity-model-client` | `client_credentials` | `py-identity-model` |
| `py-identity-model-test` | `authorization_code` | `openid`, `profile`, `py-identity-model` |

### node-oidc-provider (6 clients)

| Client ID | Grant Types | Scopes | Purpose |
|---|---|---|---|
| `test-client-credentials` | `client_credentials`, `device_code`, `token-exchange` | `openid`, `api` | Primary M2M testing |
| `test-auth-code` | `authorization_code`, `refresh_token` | `openid`, `profile`, `email`, `offline_access`, `api` | Auth code flow |
| `test-pkce-public` | `authorization_code`, `refresh_token` | `openid`, `profile`, `email`, `offline_access`, `api` | Public PKCE (no secret) |
| `test-device` | `device_code`, `refresh_token` | `openid`, `api` | Device flow |
| `test-token-exchange` | `token-exchange` | `openid`, `api` | RFC 8693 |
| `test-opaque` | `client_credentials` | `openid`, `api` | Opaque tokens for introspection/revocation |

## Infrastructure Comparison

| Aspect | IdentityServer | node-oidc-provider |
|---|---|---|
| **Base image** | `mcr.microsoft.com/dotnet/aspnet:8.0` | `node:20-alpine` |
| **Image size** | ~400 MB+ (SDK layer + runtime) | ~150 MB |
| **Startup time** | ~30-60 seconds (cert wait + .NET cold start) | ~2-3 seconds |
| **TLS requirement** | Yes — requires cert-generator service, shared volumes, PFX files | No — HTTP-only (`proxy = true`) |
| **Compose services** | 4 (cert-generator + identityserver + fastapi-app + test-runner) | 1 (node-oidc-provider) |
| **Health check** | `curl -k -f http://localhost:80/.well-known/openid-configuration` | `wget -q --spider http://localhost:9010/.well-known/openid-configuration` |
| **Dependencies** | .NET 8 SDK (build), ASP.NET runtime, Duende packages | Node.js 20, `oidc-provider`, `jose` |
| **CI overhead** | High — multi-stage Docker build, cert generation, service orchestration | Low — single container, no TLS setup |

## Licensing

| | IdentityServer (Duende) | node-oidc-provider |
|---|---|---|
| **License** | Duende Software License (commercial) | MIT |
| **Cost** | Free for dev/test; commercial license required for production use | Free |
| **Implications** | License compliance risk if fixture code is referenced as a production pattern | No restrictions |

Duende IdentityServer transitioned from the open-source IdentityServer4 to a commercial model. While the test fixture itself is not a production deployment, the licensing model adds friction and audit overhead that node-oidc-provider avoids entirely.

## Integration Test Coverage by Provider

| Test File | IdentityServer | node-oidc-provider | Ory Hydra | Descope |
|---|:---:|:---:|:---:|:---:|
| `test_discovery.py` | Yes | Yes | Yes | Yes |
| `test_aio_discovery.py` | Yes | Yes | Yes | Yes |
| `test_aio_jwks.py` | Yes | Yes | Yes | Yes |
| `test_token_client.py` | Yes | Yes | Yes | Yes |
| `test_token_validation.py` | Yes | Yes | Yes | Yes |
| `test_aio_token_validation.py` | Yes | Yes | Yes | Yes |
| `test_auth_code_pkce.py` | No | Yes | No | No |
| `test_refresh_token.py` | Partial | Yes | Yes | No |
| `test_introspection.py` | No | Yes | Yes | No |
| `test_revocation.py` | No | Yes | Yes | No |
| `test_dpop_par_jar.py` | No | Yes | No | No |
| `test_device_token_exchange.py` | No | Yes | No | No |
| `test_fapi_compliance.py` | No | Planned | No | No |
| `test_userinfo.py` | Partial | Yes | Yes | No |

**IdentityServer can run:** 6 of 14 test files (core discovery, JWKS, token client, token validation).
**node-oidc-provider can run:** 13 of 14 test files (all except FAPI 2.0 which is planned).

## Recommendation: Deprecate IdentityServer Fixture

**Action:** Deprecate and remove the IdentityServer fixture. Retain node-oidc-provider as the primary local test fixture alongside Ory Hydra and Descope as external provider targets.

**Rationale:**

1. **Redundant coverage** — Every test that runs against IdentityServer also runs against node-oidc-provider. There is no unique coverage from IdentityServer.

2. **Feature gap is permanent** — IdentityServer will never cover DPoP, PAR, JAR, Device Authorization, or Token Exchange in this fixture without significant .NET development effort. node-oidc-provider supports all of these with configuration alone.

3. **CI efficiency** — Removing the 4-service IdentityServer stack (cert-generator → identityserver → fastapi-app → test-runner) saves ~60 seconds of setup time and eliminates TLS certificate complexity.

4. **Licensing simplicity** — MIT vs commercial license removes compliance overhead.

5. **Maintenance burden** — The IdentityServer fixture requires .NET SDK updates, Duende package updates, and certificate management. node-oidc-provider requires only Node.js and two npm packages.

**Migration path:**

1. Remove `examples/identity-server/` directory
2. Remove cert-generator and identityserver services from `examples/docker-compose.test.yml`
3. Update `examples/docker-compose.test.yml` to use node-oidc-provider as the identity provider for example app tests
4. Update `docs/identity-server-example.md` with a deprecation notice or remove it
5. Update `docs/integration-tests.md` to reflect the new provider matrix

**Providers after deprecation:**

| Provider | Type | Purpose |
|---|---|---|
| node-oidc-provider | Local (Docker) | Primary: full RFC coverage, CI integration tests |
| Ory Hydra | External (cloud) | Secondary: real-world provider validation |
| Descope | External (cloud) | Secondary: production provider used by identity-stack |
