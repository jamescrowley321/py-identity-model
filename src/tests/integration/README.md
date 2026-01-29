# Integration Tests

Due to the nature of the library, the tests are written as integration tests against live OIDC providers. Currently supported providers:
- **ORY Hydra** (default for CI/CD)
- **Descope** (optional)
- **Local identity server** (for development)

All integration tests are provider-agnostic and should pass against any compliant OIDC provider.

## Testing Against ORY (Default)

# Environment Configuration
```shell
touch .env

TEST_DISCO_ADDRESS=
TEST_JWKS_ADDRESS=
TEST_CLIENT_ID=
TEST_CLIENT_SECRET=
TEST_EXPIRED_TOKEN=
TEST_AUDIENCE=
TEST_SCOPE=
```

```shell
export $(cat .env | xargs)
```

```shell
client=$(hydra \
    hydra create client \
    --endpoint http://127.0.0.1:4445/ \
    --format json \
    --grant-type client_credentials)

# We parse the JSON response using jq to get the client ID and client secret:
client_id=$(echo $client | jq -r '.client_id')
client_secret=$(echo $client | jq -r '.client_secret')

hydra \
  hydra perform client-credentials \
  --endpoint http://127.0.0.1:4444/ \
  --client-id "$client_id" \
  --client-secret "$client_secret"
```

## Testing Against Descope

### Prerequisites

1. Create a Descope account at https://www.descope.com/
2. Create a new project and note your **Project ID**
3. Configure an OAuth application with **Client Credentials** grant type
4. Note your **Client ID** and **Client Secret**

### Configuration

1. Copy the Descope environment template:
```bash
cp .env.descope.example .env.descope
```

2. Edit `.env.descope` and replace the placeholders:
```bash
# Replace YOUR_PROJECT_ID with your actual Descope project ID
TEST_DISCO_ADDRESS=https://api.descope.com/YOUR_PROJECT_ID/.well-known/openid-configuration
TEST_JWKS_ADDRESS=https://api.descope.com/YOUR_PROJECT_ID/.well-known/jwks.json

# Add your OAuth client credentials from Descope console
TEST_CLIENT_ID=your-client-id
TEST_CLIENT_SECRET=your-client-secret

# Configure scopes (add descope.claims for roles/permissions)
TEST_SCOPE=openid

# Audience is typically your Project ID
TEST_AUDIENCE=YOUR_PROJECT_ID

# Optional: Generate an expired token for expiration tests
TEST_EXPIRED_TOKEN=
```

3. Load the environment variables:
```bash
export $(cat .env.descope | xargs)
```

### Running Tests

Run all integration tests against Descope:
```bash
make test-integration-descope
```

Or run pytest directly:
```bash
uv run pytest src/tests -m integration -v -n auto
```

### Descope-Specific Notes

- **PKCE**: Descope enforces PKCE for authorization code flows (not used in integration tests, which use client credentials)
- **JWK Rotation**: Descope rotates JWKs daily with a 12-cycle window before invalidation
- **Custom Domains**: Supported on Pro/Enterprise plans - update discovery URL accordingly
- **Special Scopes**:
  - `descope.claims` - Include roles and permissions in token
  - `descope.custom_claims` - Include custom user attributes
- **Grant Types**: Authorization Code + PKCE, Client Credentials (used in tests)

### Troubleshooting

**Issue**: Tests fail with "Invalid client credentials"
- **Solution**: Verify CLIENT_ID and CLIENT_SECRET in `.env.descope`
- **Solution**: Ensure the OAuth application has Client Credentials grant enabled

**Issue**: Tests fail with "Invalid audience"
- **Solution**: Set TEST_AUDIENCE to your Descope Project ID
- **Solution**: Check that the token endpoint returns tokens with correct audience claim

**Issue**: Intermittent JWK validation failures
- **Solution**: This may occur during JWK rotation window - retry the tests
- **Solution**: Descope caches keys for 12 cycles, so failures should be rare

**Issue**: Discovery endpoint returns 404
- **Solution**: Verify PROJECT_ID is correct in the discovery URL
- **Solution**: Check if using custom domain - update URL accordingly

## Testing Against Local Identity Server

For development and testing with a local OIDC provider: