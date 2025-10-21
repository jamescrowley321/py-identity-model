# FastAPI OAuth2/OIDC Authentication Example

This example demonstrates how to integrate `py-identity-model` with FastAPI to implement OAuth2/OIDC authentication and
authorization.

## Features

- ✅ **JWT Token Validation Middleware** - Automatic token validation for protected routes
- ✅ **Dependency Injection** - Easy access to user claims and identity
- ✅ **Scope-Based Authorization** - Protect endpoints based on OAuth2 scopes
- ✅ **Claim-Based Authorization** - Enforce authorization based on specific claims
- ✅ **Token Refresh Support** - Utilities for handling token refresh flows
- ✅ **Type-Safe** - Full type hints for better IDE support
- ✅ **Production-Ready** - Best practices for security and error handling

## Prerequisites

- Python 3.12+
- A running OpenID Connect identity server (e.g., the included IdentityServer example)
- An access token for testing

## Quick Start

### 1. Install Dependencies

This example uses uv workspaces for dependency management:

```bash
# From the project root
uv sync

# This will install both the main library and the FastAPI example dependencies
```

The workspace is configured in the root `pyproject.toml` and includes:

- The main `py-identity-model` library
- The FastAPI example with its dependencies (fastapi, uvicorn)

### 2. Run with Docker Compose

The easiest way to run the complete example is using Docker Compose, which includes:
- Automatic certificate generation
- Identity Server with HTTPS
- FastAPI application with proper SSL/TLS configuration
- Integration tests

```bash
# From the examples directory
docker compose -f docker-compose.test.yml up --build

# To run tests and exit
docker compose -f docker-compose.test.yml up --build --exit-code-from test-runner
```

The certificate generator will automatically:
- Generate a self-signed CA certificate
- Create server certificates signed by the CA
- Configure all containers to trust the CA
- Store certificates in a shared Docker volume

**Note:** Certificates are stored in a Docker volume named `examples_shared-certs` and persist between runs. To regenerate certificates:

```bash
docker volume rm examples_shared-certs
docker compose -f docker-compose.test.yml up --build
```

#### SSL/TLS Configuration

The Docker setup uses proper SSL/TLS certificates with CA trust:
- The `cert-generator` service creates a CA and server certificates
- All containers mount the CA certificate and update their trust stores
- Python's `requests` library uses `REQUESTS_CA_BUNDLE` to trust the CA

**Fallback for Development:** If you need to disable SSL verification (not recommended), you can set:
```bash
DISABLE_SSL_VERIFICATION=true
```
This is useful for local development outside Docker, but the proper certificate approach is strongly preferred.

### 3. Generate a Test Token

```bash
# From the project root
python examples/generate_token.py
```

Copy the access token from the output.

### 4. Run the FastAPI Application

```bash
# From the examples/fastapi directory
python app.py
```

The API will be available at `http://localhost:8000`

### 5. Test the API

View the interactive API documentation at: http://localhost:8000/docs

Or use curl:

```bash
# Public endpoint (no auth required)
curl http://localhost:8000/

# Protected endpoint (auth required)
curl -H "Authorization: Bearer <your-token>" http://localhost:8000/api/me

# Get all claims
curl -H "Authorization: Bearer <your-token>" http://localhost:8000/api/claims

# Get user profile
curl -H "Authorization: Bearer <your-token>" http://localhost:8000/api/profile
```

## Project Structure

```
examples/fastapi/
├── app.py                     # Main FastAPI application
├── middleware.py              # Token validation middleware
├── dependencies.py            # FastAPI dependencies for auth
├── token_refresh.py           # Token refresh utilities
├── test_integration.py        # Integration tests
├── pyproject.toml             # Package configuration and dependencies
├── Dockerfile                 # Docker image for FastAPI app
├── Dockerfile.test            # Docker image for test runner
└── README.md                  # This file

examples/                      # Shared testing infrastructure
├── docker-compose.test.yml    # Docker Compose for all examples
└── run-tests.sh               # Test runner script
```

## Usage Guide

### Adding Authentication Middleware

Add the `TokenValidationMiddleware` to your FastAPI application:

```python
from fastapi import FastAPI
from middleware import TokenValidationMiddleware

app = FastAPI()

app.add_middleware(
    TokenValidationMiddleware,
    discovery_url="https://your-identity-server/.well-known/openid-configuration",
    audience="your-api-audience",
    excluded_paths=["/", "/health", "/docs", "/openapi.json"],
)
```

### Accessing User Information

Use dependency injection to access authenticated user information:

```python
from fastapi import Depends
from py_identity_model.identity import ClaimsPrincipal
from dependencies import get_current_user, get_claims


@app.get("/api/me")
async def get_me(user: ClaimsPrincipal = Depends(get_current_user)):
    return {
        "name": user.identity.name,
        "authenticated": user.identity.is_authenticated,
    }


@app.get("/api/claims")
async def get_all_claims(claims: dict = Depends(get_claims)):
    return {"claims": claims}
```

### Extracting Specific Claims

Use the claim extraction dependencies:

```python
from dependencies import get_claim_value, get_claim_values

# Get a single claim value
get_user_id = get_claim_value("sub")


@app.get("/api/profile")
async def get_profile(user_id: str = Depends(get_user_id)):
    return {"user_id": user_id}


# Get multiple values of the same claim (e.g., roles)
get_roles = get_claim_values("role")


@app.get("/api/roles")
async def get_user_roles(roles: list = Depends(get_roles)):
    return {"roles": roles}
```

### Scope-Based Authorization

Protect endpoints based on OAuth2 scopes:

```python
from dependencies import require_scope

require_read = require_scope("api.read")
require_write = require_scope("api.write")


@app.get("/api/data", dependencies=[Depends(require_read)])
async def get_data():
    return {"data": "sensitive information"}


@app.post("/api/data", dependencies=[Depends(require_write)])
async def create_data(name: str):
    return {"message": "Data created"}
```

### Claim-Based Authorization

Protect endpoints based on specific claims:

```python
from dependencies import require_claim

require_admin = require_claim("role", "admin")


@app.delete("/api/users/{user_id}", dependencies=[Depends(require_admin)])
async def delete_user(user_id: str):
    return {"message": f"User {user_id} deleted"}
```

### Token Refresh

Use the `TokenManager` for automatic token refresh:

```python
from token_refresh import TokenManager

# Initialize token manager
token_manager = TokenManager(
    discovery_url="https://your-identity-server/.well-known/openid-configuration",
    client_id="your-client-id",
    client_secret="your-client-secret",
)

# Set initial tokens
token_manager.set_tokens(
    access_token="current_access_token",
    refresh_token="current_refresh_token",
    expires_in=3600
)

# Get access token (automatically refreshes if expired)
token = await token_manager.get_access_token()
```

## Configuration

### Environment Variables

You can configure the application using environment variables:

```bash
export DISCOVERY_URL="https://your-identity-server/.well-known/openid-configuration"
export AUDIENCE="your-api-audience"
export CLIENT_ID="your-client-id"
export CLIENT_SECRET="your-client-secret"
```

### Custom Claims Validation

Add custom claims validation logic:

```python
def validate_custom_claims(claims: dict):
    """Custom claims validator."""
    # Ensure the user has a specific claim
    if "custom_claim" not in claims:
        raise Exception("Missing required custom claim")

    # Validate claim value
    if claims["custom_claim"] != "expected_value":
        raise Exception("Invalid custom claim value")


app.add_middleware(
    TokenValidationMiddleware,
    discovery_url=DISCOVERY_URL,
    audience=AUDIENCE,
    custom_claims_validator=validate_custom_claims,
)
```

## API Endpoints

### Public Endpoints

| Endpoint  | Method | Description                        |
|-----------|--------|------------------------------------|
| `/`       | GET    | Root endpoint with API information |
| `/health` | GET    | Health check endpoint              |
| `/docs`   | GET    | Interactive API documentation      |

### Protected Endpoints

| Endpoint               | Method | Description           | Requirements                     |
|------------------------|--------|-----------------------|----------------------------------|
| `/api/me`              | GET    | Get current user info | Valid token                      |
| `/api/claims`          | GET    | Get all token claims  | Valid token                      |
| `/api/token-info`      | GET    | Get token metadata    | Valid token                      |
| `/api/profile`         | GET    | Get user profile      | Valid token                      |
| `/api/data`            | GET    | Get data              | Scope: `py-identity-model`       |
| `/api/data`            | POST   | Create data           | Scope: `py-identity-model.write` |
| `/api/admin/users/:id` | DELETE | Delete user           | Role: `admin`                    |
| `/api/admin/stats`     | GET    | Get admin stats       | Role: `admin`                    |

## Error Handling

The middleware returns standard HTTP error responses:

- **401 Unauthorized**: Missing, invalid, or expired token
- **403 Forbidden**: Valid token but insufficient permissions (missing scope or claim)

Example error response:

```json
{
  "error": "Token validation failed: Token has expired",
  "status_code": 401
}
```

## Testing

### Manual Testing with curl

```bash
# Get a token
TOKEN=$(python ../generate_token.py | grep "Access Token:" -A 1 | tail -1 | xargs)

# Test public endpoint
curl http://localhost:8000/

# Test protected endpoint
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/me

# Test scope protection (should work)
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/data

# Test with missing token (should fail)
curl http://localhost:8000/api/me
```

### Testing with Python requests

```python
import requests

# Get token first
# ... (use generate_token.py)

token = "your-access-token"
headers = {"Authorization": f"Bearer {token}"}

# Test protected endpoint
response = requests.get("http://localhost:8000/api/me", headers=headers)
print(response.json())
```

## Adapting for Your Use Case

### Different Identity Provider

Update the `DISCOVERY_URL` to point to your identity provider:

```python
DISCOVERY_URL = "https://your-idp.com/.well-known/openid-configuration"
```

### Custom Audience

Set your API's expected audience:

```python
AUDIENCE = "your-api-identifier"
```

### Additional Excluded Paths

Add more paths that don't require authentication:

```python
app.add_middleware(
    TokenValidationMiddleware,
    discovery_url=DISCOVERY_URL,
    audience=AUDIENCE,
    excluded_paths=["/", "/health", "/docs", "/openapi.json", "/public/*"],
)
```

## Best Practices

1. **Always validate tokens** - Use the middleware on all protected routes
2. **Use dependency injection** - Leverage FastAPI's DI for clean code
3. **Principle of least privilege** - Only grant necessary scopes and claims
4. **Handle token refresh** - Implement proper token refresh logic for long-running operations
5. **Secure configuration** - Store secrets in environment variables, not code
6. **Error handling** - Provide clear error messages without exposing sensitive information
7. **Logging** - Log authentication failures for security monitoring

a## Testing

### Integration Tests

The example includes comprehensive integration tests that verify the OAuth/OIDC authentication flow works correctly.

#### Running Tests with Docker

The easiest way to run tests is using the included Docker Compose setup:

```bash
# From the examples directory (not examples/fastapi)
cd examples
./run-tests.sh
```

This script will:

1. Build Docker images for Identity Server, FastAPI app, and test runner
2. Start all services
3. Wait for services to be healthy
4. Run integration tests
5. Clean up containers

The Docker Compose setup is located at `examples/docker-compose.test.yml` to support
multiple examples in the future.

#### What the Tests Cover

The integration tests verify:

- ✅ Public endpoints work without authentication
- ✅ Protected endpoints reject requests without tokens
- ✅ Protected endpoints reject invalid tokens
- ✅ Protected endpoints accept valid tokens
- ✅ User claims are correctly extracted
- ✅ Scope-based authorization works
- ✅ Claim-based authorization works
- ✅ Token validation against real identity server

#### Manual Testing

You can also run the services manually for development:

```bash
# From the examples directory
cd examples

# Start services
docker-compose -f docker-compose.test.yml up -d identityserver fastapi-app

# Run tests manually
docker-compose -f docker-compose.test.yml run --rm test-runner

# Or run tests from your local machine
cd fastapi
uv sync --all-packages
uv run python test_integration.py

# Clean up
cd ..
docker-compose -f docker-compose.test.yml down -v
```

#### Test Configuration

Tests can be configured via environment variables:

- `DISCOVERY_URL`: Identity server discovery endpoint (default: https://localhost:5001/.well-known/openid-configuration)
- `FASTAPI_URL`: FastAPI application URL (default: http://localhost:8000)
- `CLIENT_ID`: OAuth client ID (default: py-identity-model-client)
- `CLIENT_SECRET`: OAuth client secret (default: py-identity-model-secret)
- `AUDIENCE`: Expected token audience (default: py-identity-model)
- `SCOPE`: OAuth scope to request (default: py-identity-model)

## Troubleshooting

### "Discovery failed" error

Make sure the identity server is running and accessible:

```bash
curl https://localhost:5001/.well-known/openid-configuration
```

### SSL certificate errors

Install the SSL certificate as trusted:

```bash
cd ../identity-server
./generate-certs.sh
```

### "Token validation failed: Token has expired"

Generate a new token:

```bash
python ../generate_token.py
```

### Import errors

Make sure py-identity-model is installed:

```bash
pip install py-identity-model
# or for development
pip install -e /path/to/py-identity-model
```

## Further Reading

- [py-identity-model Documentation](../../README.md)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [OAuth 2.0 Specification](https://oauth.net/2/)
- [OpenID Connect Specification](https://openid.net/connect/)

## License

Apache 2.0 - See LICENSE file in the project root.
