# py-identity-model
![Build](https://github.com/jamescrowley321/py-identity-model/workflows/Build/badge.svg)
![License](https://img.shields.io/pypi/l/py-identity-model)

OIDC/OAuth2.0 helper library for decoding JWTs and creating JWTs utilizing the `client_credentials` grant. This project is very limited in functionality, but it has been used in production for years as the foundation of Flask/FastAPI middleware implementations.

The use case for the library in its current form is limited to the following
* Discovery endpoint is utilized
* JWKS endpoint is utilized
* Authorization servers with multiple active keys

While you can manually construct the validation configs required to manually bypass automated discovery, the library does not currently test those scenarios.

For more information on the lower level configuration options for token validation, refer to the official [PyJWT Docs](https://pyjwt.readthedocs.io/en/stable/index.html)

Does not currently support opaque tokens.

This library inspired by [Duende.IdentityModel](https://github.com/DuendeSoftware/foss/tree/main/identity-model)

From Duende.IdentityModel
> It provides an object model to interact with the endpoints defined in the various OAuth and OpenId Connect specifications in the form of:
> * types to represent the requests and responses
> * extension methods to invoke requests
> * constants defined in the specifications, such as standard scope, claim, and parameter names
> * other convenience methods for performing common identity related operations


This library aims to provide the same features in Python.
## Examples

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

## Roadmap
These are in no particular order of importance. I am working on this project to bring a library as capable as IdentityModel to the Python ecosystem and will most likely focus on the needful and most used features first.
* Protocol abstractions and constants
* Discovery Endpoint
* Token Endpoint
* Token Introspection Endpoint
* Token Revocation Endpoint
* UserInfo Endpoint
* Dynamic Client Registration
* Device Authorization Endpoint
* Token Validation
* Example integrations with popular providers
* Example middleware implementations for Flask and FastApi
* async Support
* Setup documentation
* Opaque tokens
