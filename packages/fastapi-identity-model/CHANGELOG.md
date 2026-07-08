# Changelog

All notable changes to `fastapi-identity-model` are documented here. This project
adheres to [Semantic Versioning](https://semver.org/) and is released
independently of the core `py-identity-model` library.

## 0.1.0 (2026-07-08)

Initial release. Extracted and hardened from the `py-identity-model` FastAPI
example, then driven through the OIDF conformance suite: the RP router passes
the same local Basic RP, Config RP, and Form Post RP plans the core library is
certified against (13/13, 5/5, 13/13 — regression stage, see #437).

### Added
- `TokenValidationMiddleware` — resource-server Bearer-token validation that
  attaches a `ClaimsPrincipal` to `request.state`.
- `Depends` helpers: `get_current_user`, `get_claims`, `get_token`,
  `get_claim_value`, `get_claim_values`, `require_claim`, `require_scope`.
- `build_oidc_router` — mountable relying-party login flow (authorization code +
  PKCE) with state/nonce, ID-token validation, and UserInfo `sub` verification.
- `POST /callback` on the RP router — OAuth 2.0 `form_post` response mode,
  sharing the exact GET validation path (parsed with stdlib `parse_qsl`; no
  `python-multipart` dependency). Requires the session cookie to be issued
  with `same_site="none"` in real browsers.
- `build_oidc_router(fetch_userinfo=False)` — skip the UserInfo round-trip and
  anchor identity on the validated ID token.
- `OIDCSettings` — typed configuration with `from_env()`.
- `TokenManager` — access-token refresh lifecycle over the native async refresh grant.

### Changed vs. the former example
- Middleware returns **503** for a discovery/JWKS/network fault and **500** for a
  genuinely unexpected error, instead of masking either as a 401.
- `TokenManager` uses the async discovery + native `aio.refresh_token` grant
  (removes a blocking sync call in async context and a hand-rolled token POST).

### Security
- The RP router rejects a discovery document whose issuer does not match the
  URL it was retrieved from (OIDC Discovery 1.0 §4.3 issuer mix-up defense).
- The RP router refuses to establish a session when the token response has no
  ID token, and enforces the UserInfo `sub` match as a hard gate (a mismatch
  fails the login instead of being swallowed).
- Transient login-flow state (state/nonce/PKCE verifier) is kept under a
  separate session key from the identity and is single-use (popped on callback),
  so an in-flight login is never read as an authenticated identity.
- `TokenValidationMiddleware` rejects an ID token presented as an access token,
  requires a non-empty `audience` (a `None` audience skips `aud` enforcement for
  aud-less tokens), lets CORS preflight through, and matches excluded subpaths.
- `POST /auth/logout` (was `GET`) so a cross-site request cannot force logout.
- `TokenManager` refreshes under an `asyncio.Lock` (no concurrent-refresh
  token-family invalidation) and treats `expires_in=0` as already expired.
