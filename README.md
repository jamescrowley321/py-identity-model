# py-identity-model
![Build](https://github.com/jamescrowley321/py-identity-model/workflows/Build/badge.svg)
![License](https://img.shields.io/pypi/l/py-identity-model)

Production-grade OIDC/OAuth2.0 client library for Python. Dual sync/async API with comprehensive RFC coverage. Inspired by [Duende.IdentityModel](https://github.com/DuendeSoftware/foss/tree/main/identity-model).

## Installation

```bash
pip install py-identity-model
```

Or with uv:

```bash
uv add py-identity-model
```

**Requirements:** Python 3.12+

## Features

### Protocol Support

| Feature | RFC/Spec | Status |
|---------|----------|--------|
| OpenID Connect Discovery 1.0 | OIDC Discovery | Done |
| JSON Web Key Sets | RFC 7517 | Done |
| JWT Validation | RFC 7519 | Done |
| Client Credentials Grant | RFC 6749 | Done |
| Authorization Code + PKCE | RFC 7636 | Done |
| Refresh Token Grant | RFC 6749 | Done |
| Token Introspection | RFC 7662 | Done |
| Token Revocation | RFC 7009 | Done |
| Device Authorization | RFC 8628 | Done |
| Token Exchange | RFC 8693 | Done |
| DPoP | RFC 9449 | Done |
| Pushed Authorization Requests | RFC 9126 | Done |
| JWT Secured Authorization Request | RFC 9101 | Done |
| FAPI 2.0 Security Profile | FAPI 2.0 | Done |
| UserInfo Endpoint | OIDC Core | Done |
| OAuth Callback State Validation | RFC 6749 | Done |
| Policy-Based Configuration | — | Done |

### Architecture

- **Dual API**: Synchronous (`py_identity_model`) and asynchronous (`py_identity_model.aio`)
- **Thread-safe**: Sync uses thread-local HTTP clients; async uses singleton with lock protection
- **Modular**: Shared business logic in `core/`, thin sync/async HTTP wrappers
- **Connection pooling**: httpx-based with configurable timeouts and retry logic

## Quick Start

### Discovery

```python
from py_identity_model import DiscoveryDocumentRequest, get_discovery_document

response = get_discovery_document(DiscoveryDocumentRequest(address="https://issuer.example.com"))
if response.is_successful:
    print(f"Token Endpoint: {response.token_endpoint}")
```

### Token Validation

```python
from py_identity_model import TokenValidationConfig, validate_token

config = TokenValidationConfig(perform_disco=True, audience="my-api")
claims = validate_token(jwt=token, token_validation_config=config, disco_doc_address="https://issuer.example.com")
```

### Async API

```python
from py_identity_model.aio import get_discovery_document, validate_token
from py_identity_model import DiscoveryDocumentRequest

response = await get_discovery_document(DiscoveryDocumentRequest(address=url))
```

### Client Credentials

```python
from py_identity_model import ClientCredentialsTokenRequest, request_client_credentials_token

token = request_client_credentials_token(ClientCredentialsTokenRequest(
    client_id="my-client", client_secret="secret",
    address=token_endpoint, scope="api"
))
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HTTP_TIMEOUT` | 30.0 | Request timeout (seconds) |
| `HTTP_RETRY_COUNT` | 3 | Retries for rate-limited requests |
| `HTTP_RETRY_BASE_DELAY` | 1.0 | Base delay for exponential backoff |
| `SSL_CERT_FILE` | — | CA bundle path (recommended) |
| `REQUESTS_CA_BUNDLE` | — | CA bundle path (legacy compat) |

## Documentation

Full docs: **[jamescrowley321.github.io/py-identity-model](https://jamescrowley321.github.io/py-identity-model/)**

- [Getting Started](https://jamescrowley321.github.io/py-identity-model/getting-started/)
- [Migration Guide](https://jamescrowley321.github.io/py-identity-model/migration-guide/)
- [Performance Guide](https://jamescrowley321.github.io/py-identity-model/performance/)
- [Integration Tests](https://jamescrowley321.github.io/py-identity-model/integration-tests/)
- [API Reference](https://jamescrowley321.github.io/py-identity-model/api/)

## License

Apache License 2.0
