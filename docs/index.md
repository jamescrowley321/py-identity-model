# py-identity-model

![Build](https://github.com/jamescrowley321/py-identity-model/workflows/Build/badge.svg)
![License](https://img.shields.io/pypi/l/py-identity-model)

OIDC/OAuth2.0 helper library for decoding JWTs and creating JWTs utilizing the `client_credentials` grant. This project has been used in production for years as the foundation of Flask/FastAPI middleware implementations.

## Compliance Status

* ✅ **OpenID Connect Discovery 1.0** - Fully compliant with specification requirements
* ✅ **RFC 7517 (JSON Web Key)** - Fully compliant with JWK/JWKS specifications
* ✅ **JWT Validation** - Comprehensive validation with PyJWT integration
* ✅ **Client Credentials Flow** - OAuth 2.0 client credentials grant support

The library currently supports:

* ✅ Discovery endpoint with full validation
* ✅ JWKS endpoint with RFC 7517 compliance
* ✅ JWT token validation with auto-discovery
* ✅ Authorization servers with multiple active keys
* ✅ Client credentials token generation
* ✅ Comprehensive error handling and validation

For more information on token validation options, refer to the official [PyJWT Docs](https://pyjwt.readthedocs.io/en/stable/index.html)

**Note**: Does not currently support opaque tokens.

This library inspired by [Duende.IdentityModel](https://github.com/DuendeSoftware/foss/tree/main/identity-model)

From Duende.IdentityModel:

> It provides an object model to interact with the endpoints defined in the various OAuth and OpenId Connect specifications in the form of:
> * types to represent the requests and responses
> * extension methods to invoke requests
> * constants defined in the specifications, such as standard scope, claim, and parameter names
> * other convenience methods for performing common identity related operations

This library aims to provide the same features in Python.

## Installation

```bash
pip install py-identity-model
```

Or with uv:

```bash
uv add py-identity-model
```

## Quick Start

### Discovery

Only a subset of fields is currently mapped.

```python
import os

from py_identity_model import DiscoveryDocumentRequest, get_discovery_document

DISCO_ADDRESS = os.environ["DISCO_ADDRESS"]

disco_doc_request = DiscoveryDocumentRequest(address=DISCO_ADDRESS)
disco_doc_response = get_discovery_document(disco_doc_request)

if disco_doc_response.is_successful:
    print(f"Issuer: {disco_doc_response.issuer}")
    print(f"Token Endpoint: {disco_doc_response.token_endpoint}")
    print(f"JWKS URI: {disco_doc_response.jwks_uri}")
else:
    print(f"Error: {disco_doc_response.error}")
```

### JWKs

```python
import os

from py_identity_model import (
    DiscoveryDocumentRequest,
    get_discovery_document,
    JwksRequest,
    get_jwks,
)

DISCO_ADDRESS = os.environ["DISCO_ADDRESS"]

disco_doc_request = DiscoveryDocumentRequest(address=DISCO_ADDRESS)
disco_doc_response = get_discovery_document(disco_doc_request)

if disco_doc_response.is_successful:
    jwks_request = JwksRequest(address=disco_doc_response.jwks_uri)
    jwks_response = get_jwks(jwks_request)

    if jwks_response.is_successful:
        print(f"Found {len(jwks_response.keys)} keys")
        for key in jwks_response.keys:
            print(f"Key ID: {key.kid}, Type: {key.kty}")
    else:
        print(f"Error: {jwks_response.error}")
```

### Basic Token Validation

Token validation validates the signature of a JWT against the values provided from an OIDC discovery document. The function will raise a `PyIdentityModelException` if the token is expired or signature validation fails.

Token validation utilizes [PyJWT](https://github.com/jpadilla/pyjwt) for work related to JWT validation. The configuration object is mapped to the input parameters of `jwt.decode`.

```python
import os

from py_identity_model import (
    PyIdentityModelException,
    TokenValidationConfig,
    validate_token,
)

DISCO_ADDRESS = os.environ["DISCO_ADDRESS"]
TEST_AUDIENCE = os.environ["TEST_AUDIENCE"]

token = get_token()  # Get the token in the manner best suited to your application

validation_options = {
    "verify_signature": True,
    "verify_aud": True,
    "verify_iat": True,
    "verify_exp": True,
    "verify_nbf": True,
    "verify_iss": True,
    "verify_sub": True,
    "verify_jti": True,
    "verify_at_hash": True,
    "require_aud": False,
    "require_iat": False,
    "require_exp": False,
    "require_nbf": False,
    "require_iss": False,
    "require_sub": False,
    "require_jti": False,
    "require_at_hash": False,
    "leeway": 0,
}

validation_config = TokenValidationConfig(
    perform_disco=True,
    audience=TEST_AUDIENCE,
    options=validation_options
)

try:
    claims = validate_token(
        jwt=token,
        token_validation_config=validation_config,
        disco_doc_address=DISCO_ADDRESS
    )
    print(f"Token validated successfully for subject: {claims.get('sub')}")
except PyIdentityModelException as e:
    print(f"Token validation failed: {e}")
```

### Token Generation

The only current supported flow is the `client_credentials` flow. Load configuration parameters in the method your application supports. Environment variables are used here for demonstration purposes.

```python
import os

from py_identity_model import (
    ClientCredentialsTokenRequest,
    ClientCredentialsTokenResponse,
    DiscoveryDocumentRequest,
    get_discovery_document,
    request_client_credentials_token,
)

DISCO_ADDRESS = os.environ["DISCO_ADDRESS"]
CLIENT_ID = os.environ["CLIENT_ID"]
CLIENT_SECRET = os.environ["CLIENT_SECRET"]
SCOPE = os.environ["SCOPE"]

# First, get the discovery document to find the token endpoint
disco_doc_response = get_discovery_document(
    DiscoveryDocumentRequest(address=DISCO_ADDRESS)
)

if disco_doc_response.is_successful:
    # Request an access token using client credentials
    client_creds_req = ClientCredentialsTokenRequest(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        address=disco_doc_response.token_endpoint,
        scope=SCOPE,
    )
    client_creds_token = request_client_credentials_token(client_creds_req)

    if client_creds_token.is_successful:
        print(f"Access Token: {client_creds_token.token['access_token']}")
        print(f"Token Type: {client_creds_token.token['token_type']}")
        print(f"Expires In: {client_creds_token.token['expires_in']} seconds")
    else:
        print(f"Token request failed: {client_creds_token.error}")
else:
    print(f"Discovery failed: {disco_doc_response.error}")
```

## Code Architecture

py-identity-model uses a clean, modular architecture that separates concerns and eliminates code duplication:

### Module Structure

```
py_identity_model/
├── core/                    # Shared business logic
│   ├── models.py           # All dataclasses and models
│   ├── validators.py       # Validation functions
│   ├── parsers.py          # JWKS and response parsing
│   └── jwt_helpers.py      # JWT validation logic
├── sync/                    # Synchronous HTTP layer
│   ├── discovery.py        # Discovery document fetching
│   ├── jwks.py            # JWKS fetching
│   ├── token_client.py    # Token requests
│   └── token_validation.py # Token validation with caching
└── aio/                     # Asynchronous HTTP layer
    ├── discovery.py        # Async discovery document fetching
    ├── jwks.py            # Async JWKS fetching
    ├── token_client.py    # Async token requests
    └── token_validation.py # Async token validation with caching
```

### Design Principles

- **Separation of Concerns**: HTTP layer (sync/aio) is separate from business logic (core)
- **Code Reuse**: Both sync and async implementations share the same validators, parsers, and models
- **Type Safety**: Comprehensive type hints throughout
- **Testability**: Core business logic can be tested independently of HTTP operations

### Async Support

The library provides both synchronous and asynchronous APIs:

**Synchronous** (default):
```python
from py_identity_model import get_discovery_document, DiscoveryDocumentRequest

response = get_discovery_document(DiscoveryDocumentRequest(address=url))
```

**Asynchronous**:
```python
from py_identity_model.aio import get_discovery_document
from py_identity_model import DiscoveryDocumentRequest

response = await get_discovery_document(DiscoveryDocumentRequest(address=url))
```

See [examples/async_examples.py](../examples/async_examples.py) and [examples/sync_examples.py](../examples/sync_examples.py) for complete examples.

## Features Status

### ✅ Completed Features
* ✅ **Discovery Endpoint** - Fully compliant with OpenID Connect Discovery 1.0
* ✅ **JWKS Endpoint** - Fully compliant with RFC 7517 (JSON Web Key)
* ✅ **Token Validation** - JWT validation with auto-discovery and PyJWT integration
* ✅ **Token Endpoint** - Client credentials grant type
* ✅ **Token-to-Principal Conversion** - Convert JWTs to ClaimsPrincipal objects
* ✅ **Protocol Constants** - OIDC and OAuth 2.0 constants
* ✅ **Comprehensive Type Hints** - Full type safety throughout
* ✅ **Error Handling** - Structured exceptions and validation
* ✅ **Async/Await Support** - Full async API via `py_identity_model.aio` (v1.2.0)
* ✅ **Modular Architecture** - Clean separation between HTTP layer and business logic

### 🚧 Upcoming Features
* Token Introspection Endpoint (RFC 7662)
* Token Revocation Endpoint (RFC 7009)
* UserInfo Endpoint
* Dynamic Client Registration (RFC 7591)
* Device Authorization Endpoint
* Additional grant types (authorization code, refresh token, device flow)
* Opaque tokens support

## Documentation

* [Discovery Specification Compliance](discovery_specification_compliance_assessment.md) - ✅ **100% Compliant**
* [JWKS Specification Compliance](jwks_specification_compliance_assessment.md) - ✅ **100% Compliant**
* [Project Roadmap](py_identity_model_roadmap.md)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.
