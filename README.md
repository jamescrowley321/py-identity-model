# py-identity-model
![Build](https://github.com/jamescrowley321/py-identity-model/workflows/Build/badge.svg)
![License](https://img.shields.io/pypi/l/py-identity-model)

A Python library for OAuth2.0 and OpenID Connect (OIDC) operations, focused on JWT handling, token validation, and client credentials flow. This project provides a clean, type-safe interface for interacting with OIDC providers.

This project has been used in production for years as the foundation of Flask/FastAPI middleware implementations. The use case for the library in its current form is limited to the following:
* Discovery endpoint is utilized
* JWKS endpoint is utilized
* Authorization servers with multiple active keys

For more information on the lower level configuration options for token validation, refer to the official [PyJWT Docs](https://pyjwt.readthedocs.io/en/stable/index.html)

This library is inspired by [Duende.IdentityModel](https://github.com/DuendeSoftware/foss/tree/main/identity-model)

From Duende.IdentityModel:
> It provides an object model to interact with the endpoints defined in the various OAuth and OpenId Connect specifications in the form of:
> * types to represent the requests and responses
> * extension methods to invoke requests
> * constants defined in the specifications, such as standard scope, claim, and parameter names
> * other convenience methods for performing common identity related operations

This library aims to provide the same features in Python.

## Features

- **Discovery Document**: Fetch and parse OIDC discovery documents
- **JWKS Handling**: Retrieve and parse JSON Web Key Sets (JWKS)
- **Token Validation**: Validate JWTs using keys from JWKS endpoints
- **Token Generation**: Request tokens using the client credentials flow
- **Type Safety**: Uses Python dataclasses for request/response objects

## Installation

```bash
pip install py-identity-model
```

## Requirements

- Python 3.12+
- PyJWT
- requests
- cryptography

## Usage Examples

### Discovery Document

Fetch the OIDC discovery document from a provider:

```python
from py_identity_model import DiscoveryDocumentRequest, get_discovery_document

# Configure the discovery endpoint
disco_doc_request = DiscoveryDocumentRequest(address="https://your-provider/.well-known/openid-configuration")

# Fetch the discovery document
disco_doc_response = get_discovery_document(disco_doc_request)

if disco_doc_response.is_successful:
    print(f"Issuer: {disco_doc_response.issuer}")
    print(f"JWKS URI: {disco_doc_response.jwks_uri}")
    print(f"Token Endpoint: {disco_doc_response.token_endpoint}")
else:
    print(f"Error: {disco_doc_response.error}")
```

### JSON Web Key Sets (JWKS)

Fetch the JWKS from a provider (typically using the URI from the discovery document):

```python
from py_identity_model import (
    DiscoveryDocumentRequest,
    get_discovery_document,
    JwksRequest,
    get_jwks,
)

# First get the discovery document
disco_doc_request = DiscoveryDocumentRequest(address="https://your-provider/.well-known/openid-configuration")
disco_doc_response = get_discovery_document(disco_doc_request)

if not disco_doc_response.is_successful:
    print(f"Error fetching discovery document: {disco_doc_response.error}")
    exit(1)

# Then fetch the JWKS using the jwks_uri from the discovery document
jwks_request = JwksRequest(address=disco_doc_response.jwks_uri)
jwks_response = get_jwks(jwks_request)

if jwks_response.is_successful:
    print(f"Number of keys: {len(jwks_response.keys)}")
    for key in jwks_response.keys:
        print(f"Key ID: {key.kid}, Algorithm: {key.alg}")
else:
    print(f"Error: {jwks_response.error}")
```

### Token Validation

Validate a JWT using keys from the JWKS endpoint:

```python
from py_identity_model import (
    TokenValidationConfig,
    validate_token,
    PyIdentityModelException,
)

# Your JWT token
token = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTAifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.signature"

# Configure validation options
validation_options = {
    "verify_signature": True,
    "verify_aud": True,
    "verify_exp": True,
    "verify_iss": True,
    "require_exp": True,
    "require_iss": True,
}

# Create validation config
validation_config = TokenValidationConfig(
    perform_disco=True,  # Will fetch keys from discovery endpoint
    audience="your-audience",
    options=validation_options
)

try:
    # Validate the token
    claims = validate_token(
        jwt=token,
        token_validation_config=validation_config,
        disco_doc_address="https://your-provider/.well-known/openid-configuration"
    )

    # Access the token claims
    print(f"Subject: {claims.get('sub')}")
    print(f"Issuer: {claims.get('iss')}")
    print(f"Expiration: {claims.get('exp')}")

except PyIdentityModelException as e:
    print(f"Token validation failed: {str(e)}")
```

### Client Credentials Flow

Request a token using the client credentials flow:

```python
from py_identity_model import (
    ClientCredentialsTokenRequest,
    request_client_credentials_token,
    DiscoveryDocumentRequest,
    get_discovery_document,
)

# First get the discovery document to find the token endpoint
disco_doc_request = DiscoveryDocumentRequest(
    address="https://your-provider/.well-known/openid-configuration"
)
disco_doc_response = get_discovery_document(disco_doc_request)

if not disco_doc_response.is_successful:
    print(f"Error fetching discovery document: {disco_doc_response.error}")
    exit(1)

# Create the token request
client_creds_req = ClientCredentialsTokenRequest(
    client_id="your-client-id",
    client_secret="your-client-secret",
    address=disco_doc_response.token_endpoint,
    scope="your-scopes",  # e.g., "openid profile email"
)

# Request the token
token_response = request_client_credentials_token(client_creds_req)

if token_response.is_successful:
    # Access the token
    access_token = token_response.token.get("access_token")
    expires_in = token_response.token.get("expires_in")
    token_type = token_response.token.get("token_type")

    print(f"Access Token: {access_token[:10]}...")
    print(f"Expires In: {expires_in} seconds")
    print(f"Token Type: {token_type}")
else:
    print(f"Error: {token_response.error}")
```

## Advanced Usage

### Custom Claims Validation

You can provide a custom claims validator function:

```python
def custom_claims_validator(claims):
    if claims.get("role") != "admin":
        raise PyIdentityModelException("User is not an admin")

validation_config = TokenValidationConfig(
    perform_disco=True,
    audience="your-audience",
    options=validation_options,
    claims_validator=custom_claims_validator
)
```

### Manual Key Configuration

If you want to bypass the discovery process and provide keys manually:

```python
# Manual key configuration
key = {
    "kty": "RSA",
    "use": "sig",
    "kid": "your-key-id",
    "n": "your-modulus",
    "e": "your-exponent",
    "alg": "RS256"
}

validation_config = TokenValidationConfig(
    perform_disco=False,
    key=key,
    algorithms=["RS256"],
    audience="your-audience",
    issuer="https://your-issuer",
    options=validation_options
)
```

## Limitations

- Currently only supports the client credentials flow for token acquisition
- Limited support for discovery document fields
- Does not support opaque tokens
- No support for refresh tokens or authorization code flow yet

## Roadmap

Future development plans include:

- Full discovery document support
- Additional OAuth2.0 flows (authorization code, implicit, etc.)
- Token introspection endpoint
- Token revocation endpoint
- UserInfo endpoint
- Dynamic client registration
- Device authorization endpoint
- Async support
- Opaque token support
- Example middleware implementations for Flask and FastAPI
- Example integrations with popular providers
- Protocol abstractions and constants
- Setup documentation

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the Apache License - see the LICENSE file for details.

## Acknowledgments

This library is inspired by [Duende.IdentityModel](https://github.com/DuendeSoftware/foss/tree/main/identity-model).
