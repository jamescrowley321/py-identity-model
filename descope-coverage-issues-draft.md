# Descope Coverage - GitHub Issues Draft

This document contains draft GitHub issues for adding Descope integration tests and examples to py-identity-model.

---

## Issue 1: Add integration tests for Descope identity provider

**Labels**: `testing`, `enhancement`, `integration`

**Milestone**: v2.1.0 (or appropriate future version)

### Goal

Add integration tests that verify py-identity-model works correctly with Descope as an OIDC provider.

### Background

Currently, integration tests only run against ORY. We should add Descope as a second provider to validate:
- Library works with different OIDC providers
- Descope-specific features are handled correctly (mandatory PKCE, custom scopes)
- JWK rotation with 12-cycle window is supported

### Tasks

- [ ] Create Descope project for testing
- [ ] Configure OAuth client with client credentials grant
- [ ] Add `.env.descope.example` configuration file template
- [ ] Add GitHub Actions secrets for Descope credentials
- [ ] Create `make test-integration-descope` target in Makefile
- [ ] Add CI workflow step for Descope tests in `.github/workflows/build.yml`
- [ ] Update `src/tests/integration/README.md` with Descope setup instructions

### Configuration Needed

```bash
TEST_DISCO_ADDRESS=https://api.descope.com/{PROJECT_ID}/.well-known/openid-configuration
TEST_JWKS_ADDRESS=https://api.descope.com/{PROJECT_ID}/.well-known/jwks.json
TEST_CLIENT_ID={descope_client_id}
TEST_CLIENT_SECRET={descope_client_secret}
TEST_SCOPE=openid
TEST_AUDIENCE={PROJECT_ID}
TEST_EXPIRED_TOKEN={expired_token_for_testing}
```

### Makefile Target

```makefile
.PHONY: test-integration-descope
test-integration-descope:
	@echo "Running integration tests against Descope..."
	uv run pytest src/tests -m integration -v -n auto \
		--cov=src/py_identity_model \
		--cov-report=term-missing \
		--cov-fail-under=80
```

### GitHub Actions Configuration

Add to `.github/workflows/build.yml` after ORY tests:

```yaml
- name: Integration Tests (Descope)
  run: make test-integration-descope
  env:
    TEST_DISCO_ADDRESS: ${{ secrets.DESCOPE_DISCO_ADDRESS }}
    TEST_JWKS_ADDRESS: ${{ secrets.DESCOPE_JWKS_ADDRESS }}
    TEST_CLIENT_ID: ${{ secrets.DESCOPE_CLIENT_ID }}
    TEST_CLIENT_SECRET: ${{ secrets.DESCOPE_CLIENT_SECRET }}
    TEST_SCOPE: ${{ secrets.DESCOPE_SCOPE }}
    TEST_EXPIRED_TOKEN: ${{ secrets.DESCOPE_EXPIRED_TOKEN }}
    TEST_AUDIENCE: ${{ secrets.DESCOPE_AUDIENCE }}
```

### Descope-Specific Considerations

**Mandatory PKCE**
- Descope requires PKCE for all public clients (authorization code flow)
- Library already supports PKCE, so no code changes needed

**JWK Rotation**
- Daily rotation with 12-cycle window before invalidation
- Existing cache invalidation logic should handle this
- May occasionally see cache misses during rotation (expected behavior)

**Custom Scopes**
- Standard OIDC scopes: `openid`, `profile`, `email`
- Descope-specific: `descope.claims` (roles/permissions), `descope.custom_claims`

**Custom Domain Support**
- Optional for Pro/Enterprise plans
- Format: `https://custom.domain.com/{PROJECT_ID}/.well-known/openid-configuration`

### Success Criteria

- [ ] All existing integration tests pass against Descope
- [ ] Tests run successfully in CI/CD pipeline
- [ ] GitHub Actions secrets configured
- [ ] Documentation includes Descope setup instructions
- [ ] No library code changes required (configuration-driven)
- [ ] Maintains 80%+ test coverage

### Implementation Notes

**No code changes needed** - The integration test suite is provider-agnostic and configuration-driven. All existing tests in `src/tests/integration/` will work unmodified against Descope.

The test fixtures in `conftest.py` already handle:
- Rate limiting with retry logic
- Session-scoped caching
- Parallel execution (pytest-xdist)
- HTTP client lifecycle management

### References

- Descope OIDC Documentation: https://docs.descope.com/getting-started/oidc-endpoints
- Descope REST API: https://docs.descope.com/api
- Descope JWK Rotation: https://docs.descope.com/additional-security-features-in-descope/jwk-rotation
- Existing integration test structure: `src/tests/integration/`
- Existing ORY integration: `.github/workflows/build.yml` (lines 27-34)

---

## Issue 2: Create provider-agnostic WhoAmI example with Descope automation

**Labels**: `examples`, `documentation`, `enhancement`, `automation`

**Milestone**: v0.5.0 - Async & Examples (or appropriate future version)

### Goal

Create a simplified, provider-agnostic WhoAmI endpoint example that demonstrates the library's core value: **same code works with multiple OIDC providers** (Descope, ORY, Auth0, etc.) through configuration alone.

Additionally, provide infrastructure automation (Terraform + CLI) for Descope to enable reproducible test environments.

### Background

The library's value proposition is provider-agnostic OIDC/OAuth2 abstraction. Instead of creating provider-specific examples with custom code, we should demonstrate that:
- **Same application code** works unchanged across providers
- **Only configuration differs** (discovery URLs, environment variables)
- **Python protocols and DI** abstract provider differences cleanly
- **Automation** enables reproducible infrastructure setup

### Tasks

**Core Example (Provider-Agnostic)**
- [ ] Create `examples/whoami/` with single WhoAmI endpoint
- [ ] Implement using Python protocols for claim extraction abstraction
- [ ] Use dependency injection to show clean architecture patterns
- [ ] Single codebase that works with ALL providers
- [ ] Create provider configuration directory structure

**Provider Configurations**
- [ ] `configs/descope.env` - Descope configuration
- [ ] `configs/ory.env` - ORY Hydra configuration
- [ ] `configs/auth0.env` - Auth0 configuration (optional)
- [ ] `configs/okta.env` - Okta configuration (optional)
- [ ] Document how claim structure differs by provider (but code stays same)

**Descope Infrastructure Automation**
- [ ] Create `terraform/descope/` module for Descope resources
- [ ] Add Terraform variables for project, roles, permissions, OAuth clients
- [ ] Create CLI scripts using `descopecli` for dynamic setup
- [ ] Add `Makefile` targets for provisioning (`make provision-descope`)
- [ ] Document automation workflow (Terraform for infra, CLI for test data)

**Documentation**
- [ ] Create comprehensive README explaining the pattern
- [ ] Show protocol-based abstraction with code examples
- [ ] Document provider configuration differences
- [ ] Explain Descope automation setup (Terraform + CLI)
- [ ] Troubleshooting guide for multiple providers
- [ ] Best practices for multi-provider support

### Project Structure

```
examples/whoami/                    # Provider-agnostic WhoAmI example
├── app.py                          # Main FastAPI app (works with ALL providers)
├── protocols.py                    # Python protocols for claim extraction
├── dependencies.py                 # DI factories using protocols
├── middleware.py                   # Generic token validation
├── test_integration.py             # Tests against multiple providers
├── Dockerfile
├── pyproject.toml
├── configs/                        # Provider-specific configurations
│   ├── descope.env                 # Descope discovery URL, audience, etc.
│   ├── ory.env                     # ORY Hydra configuration
│   ├── auth0.env                   # Auth0 configuration
│   └── README.md                   # Explains configuration per provider
└── README.md                       # Pattern explanation

terraform/descope/                  # Descope infrastructure automation
├── main.tf                         # Descope provider configuration
├── variables.tf                    # Input variables
├── outputs.tf                      # Outputs (client IDs, endpoints)
├── roles.tf                        # Role definitions
├── permissions.tf                  # Permission definitions
├── oauth_clients.tf                # OAuth client configuration
└── README.md                       # Terraform usage guide

scripts/descope/                    # CLI automation scripts
├── provision.sh                    # Descope CLI provisioning script
├── create_test_user.sh             # Create test users
├── export_snapshot.sh              # Export project snapshot
└── README.md                       # CLI automation guide
```

### Provider-Agnostic Pattern to Demonstrate

**Core Principle**: Same application code works with Descope, ORY, Auth0, Okta, etc. Only configuration changes.

**1. Protocol-Based Claim Extraction**

```python
# protocols.py - Provider-agnostic interfaces
from typing import Protocol, runtime_checkable

@runtime_checkable
class ClaimExtractor(Protocol):
    """Protocol for extracting claims from tokens."""

    def extract_user_id(self, claims: dict) -> str:
        """Extract user ID from claims (provider-specific claim name)."""
        ...

    def extract_name(self, claims: dict) -> str | None:
        """Extract user name from claims."""
        ...

    def extract_email(self, claims: dict) -> str | None:
        """Extract email from claims."""
        ...
```

**2. Provider Implementations** (configuration-driven, not code!)

```python
# dependencies.py - Generic DI using configuration
from typing import Annotated
from fastapi import Depends
from py_identity_model.identity import ClaimsPrincipal

def get_claim_extractor() -> ClaimExtractor:
    """Factory: Returns claim extractor based on environment."""
    provider = os.getenv("PROVIDER_TYPE", "generic")

    # All providers use same implementation - just different claim names!
    return GenericClaimExtractor(
        user_id_claim=os.getenv("USER_ID_CLAIM", "sub"),
        name_claim=os.getenv("NAME_CLAIM", "name"),
        email_claim=os.getenv("EMAIL_CLAIM", "email"),
    )

def get_current_user(
    principal: Annotated[ClaimsPrincipal, Depends(get_claims_principal)],
    extractor: Annotated[ClaimExtractor, Depends(get_claim_extractor)]
) -> dict:
    """Extract user info - works with ALL providers."""
    claims = principal.claims
    return {
        "user_id": extractor.extract_user_id(claims),
        "name": extractor.extract_name(claims),
        "email": extractor.extract_email(claims),
    }
```

**3. Single WhoAmI Endpoint** (unchanged across providers)

```python
# app.py - Provider-agnostic application
from fastapi import FastAPI, Depends

app = FastAPI(title="WhoAmI - Provider Agnostic Example")

# Middleware configured via environment variables
app.add_middleware(
    TokenValidationMiddleware,
    discovery_url=os.getenv("DISCOVERY_URL"),  # Only config changes!
    audience=os.getenv("AUDIENCE"),
)

@app.get("/whoami")
async def whoami(user: dict = Depends(get_current_user)):
    """
    Same endpoint code works with:
    - Descope (PROVIDER_TYPE=descope)
    - ORY (PROVIDER_TYPE=ory)
    - Auth0 (PROVIDER_TYPE=auth0)
    - Okta (PROVIDER_TYPE=okta)

    Just change environment variables!
    """
    return {
        "provider": os.getenv("PROVIDER_TYPE"),
        "user": user,
        "authenticated": True,
    }
```

**4. Provider Configuration Files** (what actually differs)

```bash
# configs/descope.env
PROVIDER_TYPE=descope
DISCOVERY_URL=https://api.descope.com/${DESCOPE_PROJECT_ID}/.well-known/openid-configuration
AUDIENCE=${DESCOPE_PROJECT_ID}
USER_ID_CLAIM=sub
NAME_CLAIM=name
EMAIL_CLAIM=email

# configs/ory.env
PROVIDER_TYPE=ory
DISCOVERY_URL=https://ory-example.com/.well-known/openid-configuration
AUDIENCE=api
USER_ID_CLAIM=sub
NAME_CLAIM=name
EMAIL_CLAIM=email
```

**Key Insight**: The library abstracts provider differences. Application code stays identical.

### API Endpoints to Demonstrate

**Keep It Simple**: Single WhoAmI endpoint demonstrates the core value.

```python
@app.get("/")
async def root():
    """Public endpoint - no auth required."""
    return {
        "app": "WhoAmI - Provider Agnostic Example",
        "provider": os.getenv("PROVIDER_TYPE"),
        "discovery_url": os.getenv("DISCOVERY_URL"),
    }

@app.get("/whoami")
async def whoami(user: dict = Depends(get_current_user)):
    """
    Protected endpoint - works with ANY OIDC provider.

    Same code works with:
    - Descope: docker run -p 8000:8000 --env-file configs/descope.env whoami
    - ORY:     docker run -p 8000:8000 --env-file configs/ory.env whoami
    - Auth0:   docker run -p 8000:8000 --env-file configs/auth0.env whoami
    """
    return {
        "provider": os.getenv("PROVIDER_TYPE"),
        "user": user,
        "message": "Same code, different provider!",
    }
```

**Testing Pattern**:
```bash
# Test with Descope
export $(cat configs/descope.env | xargs)
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/whoami

# Test with ORY (same code!)
export $(cat configs/ory.env | xargs)
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/whoami
```

### Descope Infrastructure Automation

**Critical Component**: Reproducible infrastructure setup using Terraform and Descope CLI.

**1. Terraform Configuration** (`terraform/descope/`)

```hcl
# main.tf - Descope provider setup
terraform {
  required_providers {
    descope = {
      source  = "descope/descope"
      version = "~> 0.1"
    }
  }
}

provider "descope" {
  project_id = var.descope_project_id
  # Management key via DESCOPE_MANAGEMENT_KEY environment variable
}

# oauth_clients.tf - OAuth client for testing
resource "descope_application" "test_client" {
  name = "py-identity-model-test"

  oauth {
    grant_types       = ["client_credentials"]
    allowed_scopes    = ["openid", "profile", "email"]
    token_lifetime    = 3600
  }
}

output "client_id" {
  value     = descope_application.test_client.id
  sensitive = false
}

output "client_secret" {
  value     = descope_application.test_client.oauth[0].client_secret
  sensitive = true
}
```

**2. Descope CLI Scripts** (`scripts/descope/`)

```bash
#!/bin/bash
# provision.sh - Provision test environment with Descope CLI

export DESCOPE_PROJECT_ID=${DESCOPE_PROJECT_ID}
export DESCOPE_MANAGEMENT_KEY=${DESCOPE_MANAGEMENT_KEY}

# Create test users
descopecli user create \
  --login-id testuser@example.com \
  --email testuser@example.com \
  --display-name "Test User" \
  --output json

# Export project snapshot for CI/CD reproducibility
descopecli project export \
  --output-file snapshot.json

echo "Descope environment provisioned successfully"
```

**3. Makefile Integration**

```makefile
.PHONY: provision-descope
provision-descope:
	@echo "Provisioning Descope infrastructure..."
	cd terraform/descope && terraform init && terraform apply -auto-approve
	./scripts/descope/provision.sh
	@echo "Descope ready for integration tests"
```

**References**:
- [Descope Terraform Provider](https://registry.terraform.io/providers/descope/descope/latest/docs) - Official Terraform provider documentation
- [Descope CLI Documentation](https://docs.descope.com/cli/descope) - Command-line automation guide
- [Descope Management APIs](https://docs.descope.com/api/management) - API reference for programmatic control

### Testing Strategy

**Multi-Provider Integration Tests**

```python
# test_integration.py - Same tests, multiple providers
import pytest

PROVIDERS = [
    ("descope", "configs/descope.env"),
    ("ory", "configs/ory.env"),
    # ("auth0", "configs/auth0.env"),  # Optional
]

@pytest.mark.parametrize("provider_name,config_file", PROVIDERS)
def test_whoami_endpoint(provider_name, config_file):
    """Test WhoAmI endpoint works with all providers."""
    # Load provider config
    load_dotenv(config_file)

    # Get token (provider-agnostic)
    token = get_test_token()

    # Test endpoint (same assertion for all providers!)
    response = requests.get(
        "http://localhost:8000/whoami",
        headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 200
    data = response.json()
    assert data["provider"] == provider_name
    assert "user" in data
    assert data["user"]["user_id"] is not None
```

**What This Proves**:
- Same application code works across providers
- Only configuration differs
- Library successfully abstracts provider differences

### Documentation Requirements

**README Sections**

1. **Overview**
   - What the example demonstrates (provider-agnostic pattern)
   - Core value: same code, different providers

2. **The Pattern**
   - Python protocols for abstraction
   - Dependency injection for clean architecture
   - Configuration-driven provider selection

3. **Quick Start** (Multi-Provider)
   ```bash
   # Run with Descope
   docker run --env-file configs/descope.env -p 8000:8000 whoami

   # Same code with ORY
   docker run --env-file configs/ory.env -p 8000:8000 whoami
   ```

4. **Provider Configuration Guide**
   - How to configure for Descope
   - How to configure for ORY
   - How to add new providers
   - Claim mapping differences

5. **Descope Automation Setup**
   - Terraform provisioning walkthrough
   - CLI scripts usage
   - CI/CD integration
   - Snapshot management for reproducibility

6. **Critical Provider-Specific Considerations**

   **Descope PKCE Requirement** ⚠️
   - Descope **mandates PKCE for all public clients** (authorization code flow)
   - This library already supports PKCE (no code changes needed)
   - Reference: [Descope OIDC Endpoints](https://docs.descope.com/getting-started/oidc-endpoints)
   - Reference: [Dynamic Client Registration](https://www.descope.com/learn/post/dynamic-client-registration)

   **Descope JWK Rotation Strategy** ⚠️
   - **Daily rotation** with **12-cycle window** before invalidation
   - After 12 rotations, active sessions with older keys require re-authentication
   - Library's cache invalidation handles this automatically
   - May see occasional cache misses during rotation (expected behavior)
   - Reference: [Descope JWK Rotation](https://docs.descope.com/additional-security-features-in-descope/jwk-rotation)

   **Custom Domains** (Pro/Enterprise)
   - Format: `https://custom.domain.com/{PROJECT_ID}/.well-known/openid-configuration`
   - Reference: [Descope Custom Domains](https://docs.descope.com/managing-environments)

7. **Testing**
   - Running tests against multiple providers
   - Automated infrastructure provisioning
   - Snapshot export/import workflow

8. **Troubleshooting**
   - Provider-specific issues
   - Configuration debugging
   - Common pitfalls

### Success Criteria

- [ ] Provider-agnostic WhoAmI example in `examples/whoami/`
- [ ] **Same application code** works with Descope, ORY, and optionally Auth0/Okta
- [ ] Python protocols demonstrate clean abstraction patterns
- [ ] Configuration files for each provider (`configs/*.env`)
- [ ] Terraform module provisions Descope infrastructure
- [ ] CLI scripts automate Descope test environment setup
- [ ] Integration tests validate against multiple providers
- [ ] Comprehensive documentation with provider configuration guide
- [ ] Critical Descope considerations documented with source references:
  - PKCE requirement ([docs](https://docs.descope.com/getting-started/oidc-endpoints))
  - JWK rotation 12-cycle window ([docs](https://docs.descope.com/additional-security-features-in-descope/jwk-rotation))
  - Custom domain support ([docs](https://docs.descope.com/managing-environments))
- [ ] Automation enables reproducible CI/CD setup

### Implementation Notes

**Core Philosophy**: Demonstrate the library's value by showing **one codebase, many providers**.

**Key Principles**:
- No provider-specific code in application logic
- Protocols abstract claim extraction differences
- Dependency injection enables testability
- Configuration drives provider selection
- Automation enables reproducible infrastructure

**Why This Matters**:
- Users see that **the library works** - no custom code needed per provider
- Clean architecture patterns (protocols, DI) are demonstrated
- Infrastructure-as-code approach is production-ready
- Multi-provider testing validates library's core promise

### References

**Descope OIDC/OAuth2 Documentation**:
- [OIDC Endpoints](https://docs.descope.com/getting-started/oidc-endpoints) - Discovery, token, userinfo endpoints
- [REST API Reference](https://docs.descope.com/api) - Complete API documentation
- [Dynamic Client Registration](https://www.descope.com/learn/post/dynamic-client-registration) - OAuth client provisioning

**Critical Descope Features** (⚠️ referenced in documentation):
- [JWK Rotation Strategy](https://docs.descope.com/additional-security-features-in-descope/jwk-rotation) - Daily rotation, 12-cycle window
- [Session Management](https://docs.descope.com/authorization/session-management) - Session lifecycle and refresh

**Descope Infrastructure Automation**:
- [Terraform Provider](https://registry.terraform.io/providers/descope/descope/latest/docs) - Official Terraform provider
- [Terraform Provider GitHub](https://github.com/descope/terraform-provider-descope) - Source code and examples
- [Descope CLI Documentation](https://docs.descope.com/cli/descope) - Command-line automation
- [Descope CLI GitHub](https://github.com/descope/descopecli) - CLI source and installation
- [Management APIs - Permissions](https://docs.descope.com/api/management/permissions) - Programmatic permission management
- [Management APIs - Roles](https://docs.descope.com/api/management/roles) - Programmatic role management
- [Environment Management](https://docs.descope.com/managing-environments) - Multi-environment setup, custom domains
- [GitHub Environment Management](https://docs.descope.com/managing-environments/manage-envs-in-github) - CI/CD integration patterns

**Protocol/Architecture Patterns**:
- [Python Protocols (PEP 544)](https://peps.python.org/pep-0544/) - Structural subtyping
- [FastAPI Dependency Injection](https://fastapi.tiangolo.com/tutorial/dependencies/) - DI patterns

**Existing Examples**:
- Generic FastAPI example: `examples/fastapi/`
- Integration test patterns: `src/tests/integration/`

---

## Next Steps

1. **Review & Edit**: Review this document and refine as needed
2. **Create GitHub Issues**: Copy Issue #1 and Issue #2 to GitHub with proper labels and milestones
3. **Prioritize**:
   - **Start with Issue #1** (integration tests) - Fastest to implement, validates library against Descope
   - **Then Issue #2** (WhoAmI example + automation) - Demonstrates provider-agnostic value
4. **Implementation Order**:
   - Phase 1: Integration tests (configuration-driven, ~4-6 hours)
   - Phase 2: WhoAmI example application (~8-10 hours)
   - Phase 3: Descope automation (Terraform + CLI, ~6-8 hours)
   - Phase 4: Documentation and multi-provider testing (~4-6 hours)

## Value Proposition

**Why This Approach**:
- **Validates library's core promise**: Same code works across providers
- **Clean architecture demonstration**: Protocols, DI, configuration-driven design
- **Production-ready patterns**: Infrastructure-as-code, reproducible environments
- **Comprehensive documentation**: Critical provider considerations with source references

**What Makes This Different from Other Provider Examples** (issues #35-40):
- Not "Auth0 example" or "Okta example" - a **pattern example** that works with ALL providers
- Shows the library's value: provider abstraction
- Includes infrastructure automation (Descope as reference implementation)
- Documents critical provider-specific considerations with proper citations

## Notes

- Both issues align with existing roadmap philosophy
- Integration tests require **zero code changes** (configuration-driven validation)
- WhoAmI example demonstrates **one codebase, many providers** pattern
- Descope automation provides **reproducible infrastructure** template
- Descope free tier available for testing
- All critical Descope features (PKCE, JWK rotation, custom domains) documented with source references
