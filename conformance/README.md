# OIDC RP Conformance Test Harness

Test infrastructure for running the [OpenID Foundation conformance suite](https://openid.net/certification/testing/) against py-identity-model.

## Architecture

- **Conformance suite** — OIDF Java server + MongoDB + nginx (TLS termination)
- **RP harness** — Thin FastAPI app using py-identity-model's sync API
- **Test runner** — Python script that orchestrates test plans via the suite's REST API

## Quick Start

```bash
# From the repo root:
make conformance-build    # Build containers
make conformance-up       # Start the suite + RP harness
make conformance-down     # Tear down

# Run conformance tests:
cd conformance
python run_tests.py --plan basic-rp
python run_tests.py --plan config-rp
```

## DNS

The conformance suite uses `localhost.emobix.co.uk` which resolves to `127.0.0.1`. No `/etc/hosts` changes needed.

## Test Plans

| Plan | Config | Description |
|------|--------|-------------|
| `basic-rp` | `configs/basic-rp.json` | Basic RP certification (code flow, client_secret_basic) |
| `config-rp` | `configs/config-rp.json` | Config RP certification (discovery-based config) |

## Profile Test Counts

### Basic RP

The Basic RP certification plan runs a variable number of tests depending on variant
configuration (response type, client auth type, etc.). With the `code` response type and
`client_secret_basic` auth, the plan produces the standard set of tests covering token
validation, key rotation, scope handling, and userinfo.

### Config RP

The Config RP certification plan contains exactly **6 tests**. This is the complete profile
as defined by the conformance suite source (`OIDCCClientConfigTestPlan.java`) and the
[OpenID Connect Conformance Profiles v3.0](https://openid.net/certification/testing/) (Section 3.2).

| Test | Description | Expected Result |
|------|-------------|-----------------|
| `oidcc-client-test-discovery-openid-config` | Fetch and parse discovery document | PASS |
| `oidcc-client-test-discovery-issuer-mismatch` | Detect issuer mismatch in discovery | PASS |
| `oidcc-client-test-discovery-jwks-uri-keys` | Fetch and parse JWKS from discovery | PASS |
| `oidcc-client-test-idtoken-sig-none` | Handle unsigned ID tokens (alg:none) | SKIP (secure default) |
| `oidcc-client-test-signing-key-rotation` | Handle OP signing key rotation | PASS |
| `oidcc-client-test-signing-key-rotation-just-before-signing` | Handle key rotation immediately before signing | PASS |

The SKIP on `oidcc-client-test-idtoken-sig-none` is expected — py-identity-model correctly
rejects unsigned tokens, which is the secure default. The conformance suite auto-skips this
test when the RP does not advertise support for `alg:none`.

Three additional test classes exist in the suite's `openid/client/config/` directory but are
excluded from the Config RP plan because they require dynamic client registration
(WebFinger account/URL discovery and dynamic registration tests). These belong to the
Dynamic RP profile only.

## Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `GET /` | GET | Health check |
| `GET /authorize` | GET | Start auth flow (redirect to OP) |
| `GET /callback` | GET | Handle authorization callback |
| `POST /callback` | POST | Handle form_post callback |
| `GET /results/{test_id}` | GET | Retrieve test flow results |
