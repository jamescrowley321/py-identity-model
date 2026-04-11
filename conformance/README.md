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

## Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `GET /` | GET | Health check |
| `GET /authorize` | GET | Start auth flow (redirect to OP) |
| `GET /callback` | GET | Handle authorization callback |
| `POST /callback` | POST | Handle form_post callback |
| `GET /results/{test_id}` | GET | Retrieve test flow results |

## Hosted certification token rotation

For cert-grade runs against `https://www.certification.openid.net/` (the hosted
OIDF suite) the runner needs a Bearer token. The token is created by an
interactive browser session against the hosted suite — there is no headless
API to create one because the creation endpoint itself requires an
OIDC-authenticated browser session.

`scripts/rotate_conformance_token.py` automates the non-interactive parts of
that flow: persistent browser profile, token creation via the suite's UI,
and pushing the resulting secret to HCP Vault Secrets.

```bash
# First run — interactive Google/GitLab sign-in in the browser window
uv run conformance/scripts/rotate_conformance_token.py

# Subsequent runs — persistent profile keeps you signed in
uv run conformance/scripts/rotate_conformance_token.py --headless

# Dry run — create the token but print (masked) instead of pushing to Vault
uv run conformance/scripts/rotate_conformance_token.py --dry-run
```

**Prerequisites:**
- `uv` (PEP 723 inline dependency support)
- Playwright Chromium binary: `uv run --with playwright playwright install chromium`
- HCP CLI installed and authenticated: `hcp auth login` + `hcp profile init`
- HCP Vault Secrets app configured (default name: `py-identity-model`)

See the script's module docstring for full design notes and flag reference.
