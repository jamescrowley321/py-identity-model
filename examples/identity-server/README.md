# IdentityServer Example for E2E Testing

This directory contains a Docker Compose setup for running Duende IdentityServer for end-to-end testing with the py-identity-model library.

## Files

- `docker-compose.e2e.yml` - Docker Compose configuration for IdentityServer
- `Dockerfile` - Docker build configuration for custom IdentityServer image
- `IdentityServer.csproj` - .NET project file with Duende IdentityServer dependencies
- `Program.cs` - IdentityServer application bootstrap code
- `Config.cs` - IdentityServer client and scope configuration
- `appsettings.json` - IdentityServer application settings

## Usage

### SSL Certificate Setup

Before starting IdentityServer, generate SSL certificates for HTTPS:

```bash
cd examples/identity-server
./generate-certs.sh
```

This creates self-signed certificates in the `certs/` directory for local development.

### Start IdentityServer

From the project root directory:

```bash
cd examples/identity-server
docker-compose -f docker-compose.e2e.yml up -d
```

### Stop IdentityServer

```bash
docker-compose -f docker-compose.e2e.yml down
```

## Configuration

The IdentityServer is configured with:

- **HTTPS Port**: 5001 (HTTPS)
- **HTTP Port**: 5000 (HTTP, for fallback)
- **Discovery Endpoint**: https://localhost:5001/.well-known/openid-configuration
- **JWKS Endpoint**: https://localhost:5001/.well-known/jwks.json
- **Token Endpoint**: https://localhost:5001/connect/token

### Clients

Two test clients are configured:

1. **py-identity-model-client** (Client Credentials)
   - Client ID: `py-identity-model-client`
   - Client Secret: `py-identity-model-secret`
   - Scopes: `py-identity-model`

2. **py-identity-model-test** (Authorization Code)
   - Client ID: `py-identity-model-test`
   - Client Secret: `test-secret`
   - Scopes: `openid`, `profile`, `py-identity-model`
   - Redirect URI: `https://localhost:5002/signin-oidc`

## Health Check

The container includes a health check that verifies the discovery endpoint is accessible. Wait for the container to be healthy before running tests.

## Testing

Use this setup for integration and E2E testing of the py-identity-model library against a real IdentityServer instance.