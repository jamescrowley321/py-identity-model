# Changelog

All notable changes to `fastapi-identity-model` are documented here. This project
adheres to [Semantic Versioning](https://semver.org/) and is released
independently of the core `py-identity-model` library.

## 0.1.0 (unreleased)

Initial release. Extracted and hardened from the `py-identity-model` FastAPI example.

### Added
- `TokenValidationMiddleware` — resource-server Bearer-token validation that
  attaches a `ClaimsPrincipal` to `request.state`.
- `Depends` helpers: `get_current_user`, `get_claims`, `get_token`,
  `get_claim_value`, `get_claim_values`, `require_claim`, `require_scope`.
- `build_oidc_router` — mountable relying-party login flow (authorization code +
  PKCE) with state/nonce, ID-token validation, and UserInfo `sub` verification.
- `OIDCSettings` — typed configuration with `from_env()`.
- `TokenManager` — access-token refresh lifecycle over the native async refresh grant.

### Changed vs. the former example
- Middleware now returns **500** (not 401) for unexpected server-side failures.
- `TokenManager` uses the async discovery + native `aio.refresh_token` grant
  (removes a blocking sync call in async context and a hand-rolled token POST).
