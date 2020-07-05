# py-identity-model

WIP - OIDC helper library. This project is very immature and rough, so check back in periodically as more features and documentation are added.

TODO:

* See GitHub issues

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

If an `alg` value is not provided as part of the JWKs discovery document, `RS256` is assumed.

```python
import os

from py_oidc import PyOidcException, validate_token

DISCO_ADDRESS = os.environ["DISCO_ADDRESS"]

token = get_token() # Get the token in the manner best suited to your application

claims = validate_token(jwt=token, disco_doc_address)
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



