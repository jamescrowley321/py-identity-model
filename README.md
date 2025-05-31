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

from src.py_identity_model import DiscoveryDocumentRequest, get_discovery_document

DISCO_ADDRESS = os.environ["DISCO_ADDRESS"]

disco_doc_request = DiscoveryDocumentRequest(address=DISCO_ADDRESS)
disco_doc_response = get_discovery_document(disco_doc_request)
print(disco_doc_response)
```

### JWKs

```python
import os

from src.py_identity_model import (
    DiscoveryDocumentRequest,
    get_discovery_document,
    JwksRequest,
    get_jwks,
)

DISCO_ADDRESS = os.environ["DISCO_ADDRESS"]

disco_doc_request = DiscoveryDocumentRequest(address=DISCO_ADDRESS)
disco_doc_response = get_discovery_document(disco_doc_request)

jwks_request = JwksRequest(address=disco_doc_response.jwks_uri)
jwks_response = get_jwks(jwks_request)
print(jwks_response)
```

### Basic Token Validation

Token validation validates the signature of a JWT against the values provided from an OIDC discovery document. The function will throw an exception if the token is expired or signature validation fails.

Token validation utilizes [PyJWT](https://github.com/jpadilla/pyjwt) for work related to JWT validation. The configuration object is mapped to the input parameters of `jose.jwt.decode`. 

```python
@dataclass
class TokenValidationConfig:
    perform_disco: bool
    key: Optional[dict] = None
    audience: Optional[str] = None
    algorithms: Optional[List[str]] = None
    issuer: Optional[str] = None
    subject: Optional[str] = None
    options: Optional[dict] = None
    claims_validator: Optional[Callable] = None
```

```python
import os

from src.py_identity_model import PyIdentityModelException, validate_token

DISCO_ADDRESS = os.environ["DISCO_ADDRESS"]

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

claims = validate_token(jwt=token, disco_doc_address=DISCO_ADDRESS)
print(claims)
```

### Token Generation

The only current supported flow is the `client_credentials` flow. Load configuration parameters in the method your application supports. Environment variables are used here for demonstration purposes.

Example:

```python
import os

from src.py_identity_model import (
    ClientCredentialsTokenRequest,
    request_client_credentials_token,
    get_discovery_document,
    DiscoveryDocumentRequest,
)

DISCO_ADDRESS = os.environ["DISCO_ADDRESS"]
CLIENT_ID = os.environ["CLIENT_ID"]
CLIENT_SECRET = os.environ["CLIENT_SECRET"]
SCOPE = os.environ["SCOPE"]

disco_doc_response = get_discovery_document(
    DiscoveryDocumentRequest(address=DISCO_ADDRESS)
)

client_creds_req = ClientCredentialsTokenRequest(
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    address=disco_doc_response.token_endpoint,
    scope=SCOPE,
)
client_creds_token = request_client_credentials_token(client_creds_req)
print(client_creds_token)
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
