# OIDC RP Conformance Test Harness

Test infrastructure for running the [OpenID Foundation conformance suite](https://openid.net/certification/testing/) against py-identity-model.

## Architecture

- **Conformance suite** — OIDF Java server + MongoDB + Apache httpd (TLS termination)
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

## Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `GET /` | GET | Health check |
| `GET /authorize` | GET | Start auth flow (redirect to OP) |
| `GET /callback` | GET | Handle authorization callback |
| `POST /callback` | POST | Handle form_post callback |
| `GET /results/{test_id}` | GET | Retrieve test flow results |
