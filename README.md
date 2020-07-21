# py-identity-model
![Build](https://github.com/jamescrowley321/py-identity-model/workflows/Build/badge.svg)
![License](https://img.shields.io/pypi/l/py-identity-model)

WIP - OIDC helper library. This project is very immature and rough, so check back in periodically as more features and documentation are added.

Inspired By:

* [IdentityModel](https://github.com/IdentityModel/IdentityModel)
* [cognitojwt](https://github.com/borisrozumnuk/cognitojwt)

## Examples

### Discovery

Only a subset of fields is currently mapped.

```python
import os

from py_identity_model import DiscoveryDocumentRequest, get_discovery_document

DISCO_ADDRESS = os.environ["DISCO_ADDRESS"]
    
disco_doc_request = DiscoveryDocumentRequest(address=DISCO_ADDRESS)
disco_doc_response = get_discovery_document(disco_doc_request)    
print(disco_doc_response)
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

jwks_request = JwksRequest(address=disco_doc_response.jwks_uri)
jwks_response = get_jwks(jwks_request)
print(jwks_response)
```

### Basic Token Validation

Token validation validates the signature of a JWT against the values provided from an OIDC discovery document. The function will throw an exception if the token is expired or signature validation fails.

Token validation is simply a wrapper on top of the [jose.jwt.decode](https://python-jose.readthedocs.io/en/latest/jwt/api.html#jose.jwt.decode). The configuration object is mapped to the input parameters of `jose.jwt.decode`. 

```python
@dataclass
class TokenValidationConfig:
    perform_disco: bool
    key: Optional[dict] = None
    audience: Optional[str] = None
    algorithms: Optional[List[str]] = None
    issuer: Optional[List[str]] = None
    subject: Optional[str] = None
    options: Optional[dict] = None
```



```python
import os

from py_identity_model import PyIdentityModelException, validate_token

DISCO_ADDRESS = os.environ["DISCO_ADDRESS"]

token = get_token() # Get the token in the manner best suited to your application

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

from py_identity_model import (
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
