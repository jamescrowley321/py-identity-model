# API Reference

Auto-generated reference documentation for the `py-identity-model` public API.

The library provides both **synchronous** and **asynchronous** APIs. All models (requests, responses, config) are shared between the two.

## Sync API (default)

```python
from py_identity_model import get_discovery_document, DiscoveryDocumentRequest
```

## Async API

```python
from py_identity_model.aio import get_discovery_document
from py_identity_model import DiscoveryDocumentRequest
```

## Modules

| Module | Description |
|--------|-------------|
| [Auth Code + PKCE](auth-code-pkce.md) | Authorization code grant with PKCE (RFC 7636) |
| [Authorize Callback](authorize-callback.md) | Authorization callback parsing and state validation |
| [HTTP Client](http-client.md) | Dependency injection for HTTP client management |
| [Introspection](introspection.md) | Token Introspection (RFC 7662) |
| [PAR](par.md) | Pushed Authorization Requests (RFC 9126) |
| [DPoP](dpop.md) | Demonstrating Proof of Possession (RFC 9449) |
| [Discovery](discovery.md) | OpenID Connect Discovery 1.0 document fetching |
| [JWKS](jwks.md) | JSON Web Key Set (RFC 7517) operations |
| [Refresh Token](refresh-token.md) | Refresh Token Grant (RFC 6749 Section 6) |
| [Revocation](revocation.md) | Token Revocation (RFC 7009) |
| [Token Client](token-client.md) | OAuth 2.0 token endpoint (client credentials) |
| [Token Validation](token-validation.md) | JWT validation with auto-discovery |
| [UserInfo](userinfo.md) | OpenID Connect UserInfo endpoint |
| [Identity & Claims](identity.md) | Claims-based identity model |
| [Exceptions](exceptions.md) | Exception hierarchy |
