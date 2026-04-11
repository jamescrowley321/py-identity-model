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
for our variant configuration, as defined by the conformance suite source
([`OIDCCClientConfigTestPlan.java`](https://gitlab.com/openid/conformance-suite/-/blob/master/src/main/java/net/openid/conformance/openid/client/OIDCCClientConfigTestPlan.java))
and the [OpenID Connect Conformance Profiles v3.0](https://openid.net/wordpress-content/uploads/2018/06/OpenID-Connect-Conformance-Profiles.pdf).

#### Variant configuration

Our `config-rp.json` runs the plan with these variant parameters (see [`configs/config-rp.json`](configs/config-rp.json)):

| Variant parameter | Our value | Effect on test selection |
|---|---|---|
| `client_registration` | `static_client` | Excludes dynamic client registration tests |
| `client_auth_type` | `client_secret_basic` | Standard HTTP Basic auth at the token endpoint |
| `request_type` | `plain_http_request` | Plain authorization requests (not `request_object` / `request_uri`) |
| `response_mode` | `default` | Default response mode for the Config RP profile |

These are the cert-grade variant settings for a Config RP submission — they are the same
values used by other certified RP libraries (see e.g. `erlef/oidcc_conformance`'s submitted
certifications). Changing any of them would narrow or broaden the test set.

#### Test matrix

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

#### Tests excluded by this variant

Three additional test classes exist in the suite's `openid/client/config/` directory but
are excluded from our plan because of the `static_client` variant choice and the Config RP
profile's scope:

- **`OIDCCClientTestDynamicRegistration`** — excluded because our variant is
  `client_registration=static_client`. This test requires the RP to dynamically register
  itself with the OP per RFC 7591. It is `@VariantNotApplicable` when `client_registration`
  is `static_client`, so the conformance suite omits it from the plan automatically. This
  test belongs to the **Dynamic RP** profile.
- **`OIDCCClientTestDiscoveryWebfingerAcct`** — excluded because Config RP uses static
  `.well-known/openid-configuration` discovery. WebFinger discovery (RFC 7033) is a
  separate mechanism where the RP discovers the OP from a user-supplied `acct:` URI. It
  is not part of Config RP's scope regardless of variant choice.
- **`OIDCCClientTestDiscoveryWebfingerURL`** — excluded for the same reason as the `Acct`
  variant: WebFinger URL-style discovery is out of scope for Config RP, which tests the
  `.well-known/openid-configuration` discovery path only.

If we wanted to certify WebFinger discovery behavior, it would require a separate
profile and test plan — py-identity-model does not currently implement WebFinger discovery
and it is not in the current certification scope (see [#242](https://github.com/jamescrowley321/py-identity-model/issues/242)).

## Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `GET /` | GET | Health check |
| `GET /authorize` | GET | Start auth flow (redirect to OP) |
| `GET /callback` | GET | Handle authorization callback |
| `POST /callback` | POST | Handle form_post callback |
| `GET /results/{test_id}` | GET | Retrieve test flow results |
