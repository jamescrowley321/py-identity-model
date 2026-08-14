# Load / Soak Suite (TH-1.5)

A Locust-driven load and soak harness for the token-validation stack (#474, epic
#462, design §4/§5). It swarms the booted `fastapi-identity-model` resource
server (RS) with a **pre-minted token pool** — mint each token class once, replay
it many times — because real IdPs rate-limit per-request minting while JWT
validation is stateless, so replay is valid load. Each run reports RPS, latency
percentiles, error-rate-by-class, cache-hit rate, and upstream discovery/JWKS
fetch volume.

**Split of responsibility:** pytest owns correctness and deterministic behaviour
proofs (LRU, mix-up, `private_key_jwt`); this suite owns load and soak.

## Layout

| Module | Role |
|--------|------|
| `scenarios.py` | The S1–S12 catalogue, run profiles, and the expected-status map (authoritative profile split — see below). |
| `pool.py` | The pre-minted replay pool (mint once, replay many). |
| `locustfile.py` | A standalone Locust file the runner drives as a subprocess. |
| `runner.py` | Orchestration (fresh mock OP + booted RS per scenario), metric collection, and SLO gate evaluation. |
| `test_load_ci_short.py` | The CI-short pytest entrypoint (real Locust run over the CI_SHORT profile). |

## How to run

```bash
make test-harness-load
```

which runs the CI-short profile through a real Locust process against the booted
RS + mock OP:

```bash
uv run --group load --all-packages pytest src/tests/load/test_load_ci_short.py \
    -m integration -p no:benchmark -v
```

Two things make the invocation non-obvious:

- **`load` dependency group.** Locust lives in the opt-in `load` group
  (`uv run --group load …`), not the root test dependencies. Locust pulls in
  gevent, which monkey-patches the stdlib, so it must stay out of the default
  environment. The suite skips cleanly (`importlib.util.find_spec("locust")`)
  when the group is not installed.
- **Locust runs OUT of process.** The runner drives Locust as a `subprocess`
  (`locust --headless -f locustfile.py`) and **never imports it in-process**.
  Importing locust triggers gevent's `monkey.patch_all()`, which deadlocks the
  parent's in-process asyncio mock-OP server thread. Keeping Locust in its own
  process isolates gevent's patched world; the pre-minted pool and the run
  summary cross the process boundary as JSON files.

Each scenario runs against a **fresh** mock OP + RS, so caches start empty and no
failure-injection state bleeds across scenarios.

### Nightly / on-demand profiles

`make test-harness-load-nightly` prints the on-demand command for the NIGHTLY
soak profile (S7/S11/S12) — a documented, not-scheduled hook (#271). The
DIAGNOSTIC and NIGHTLY profiles are run directly via `run_profile`:

```bash
uv run --group load --all-packages python -c \
  'from src.tests.load.runner import run_profile; from src.tests.load.scenarios import Profile; \
   [print(r) for r in run_profile(Profile.NIGHTLY)]'
```

## Profile split

Scenarios are grouped into three run profiles. The authoritative assignment lives
in `scenarios.py`; this table mirrors it.

| Profile | Scenarios | Purpose |
|---------|-----------|---------|
| **CI_SHORT** | S1, S2, S3, S6, S8 | The PR gate: short (~3s), deterministic, mock-OP-backed, self-contained (no Docker). |
| **DIAGNOSTIC** | S5, S9, S10 | Head-of-line / no-store / blocking-validator probes, run on demand. |
| **NIGHTLY** | S4, S7, S11, S12 | TTL-refresh / LRU-thrash / RSS-FD soak / multi-tenant runs, run on demand (feeds #271). |

| ID | Title | Profile | Proves |
|----|-------|---------|--------|
| S1 | warm RPS ceiling (valid RS256, hot cache) | CI_SHORT | warm p99 knee + RPS/worker with a fully hot cache |
| S2 | alg cost (RS256 vs ES256, warm) | CI_SHORT | the ES256/RS256 warm-validation cost ratio |
| S3 | cold stampede (empty cache, burst) | CI_SHORT | single-flight: a cold burst fetches discovery + JWKS once each |
| S4 | TTL refresh under load (60s TTL rollover) | NIGHTLY | mid-load TTL rollover stays single-flight, spikes no errors |
| S5 | provider-slowness head-of-line blocking | DIAGNOSTIC | bounded cohort stall while the single-flight holder retries |
| S6 | kid-rotation storm + unknown-kid flood | CI_SHORT | unknown-kid flood recovers within ~1 cooldown, caps upstream fetches, 401s cleanly |
| S7 | LRU thrash > 64 issuers | NIGHTLY | bounded memory under > 64 distinct issuers |
| S8 | rejection correctness & uniformity under contention | CI_SHORT | every class returns its correct status, uniform 401 body, zero 500s |
| S9 | discovery no-store (re-fetch every request) | DIAGNOSTIC | no-store discovery collapses throughput while JWKS stays cached |
| S10 | blocking claims_validator (event-loop stall) | DIAGNOSTIC | **SCAFFOLD — not implemented** (see below) |
| S11 | RSS / FD soak | NIGHTLY | flat RSS/FD for a single issuer; bounded churn at 64 issuers |
| S12 | multi-tenant + issuer mix-up | NIGHTLY | tenant LRU survival + RFC 9207 cross-issuer rejection under load |

Two placement notes:

- **S4 is NIGHTLY-only.** The cache enforces a hard 60s minimum TTL
  (`core.jwks_cache.MIN_CACHE_TTL_SECONDS`), so a genuine TTL rollover cannot
  happen inside a ~3s CI-short window — S4 needs a >60s run.
- **S10 is an unimplemented scaffold.** Proving a synchronous custom claims
  validator stalls the event loop needs a blocking validator wired into the RS
  app, which does not exist yet. The row is a DIAGNOSTIC-only placeholder, never
  gated, and drives no assertion. Do **not** treat it as coverage.

## Calibrated SLO baseline

The numbers below are measured from a DoD Locust run of `run_profile(CI_SHORT)`
with 1 worker (mock OP + booted RS, no Docker). They are the baseline the SLO
gates are calibrated against.

| Scenario | req | fail | RPS | p50 | p95 | p99 | 5xx | upstream fetches |
|----------|-----|------|-----|-----|-----|-----|-----|------------------|
| S1 warm RPS ceiling (valid RS256) | 4755 | 0 | 1644.6 | 4ms | 7ms | 10ms | 0 | 0 (all cache hits) |
| S2 alg cost (RS256 vs ES256) | 4488 | 0 | 1553.4 | 4ms | 7ms | 9ms | 0 | 0 |
| S3 cold stampede (single-flight) | 4676 | 0 | 1618.2 | 8ms | 13ms | 24ms | 0 | discovery=1, jwks=1 (coalesced) |
| S6 kid-rotation storm | 6049 | 0 | 2088.3 | 3ms | 7ms | 13ms | 0 | discovery=1, jwks=8 (~1/cooldown) |
| S8 rejection uniformity under contention | 6568 | 0 | 2273.1 | 5ms | 14ms | 19ms | 0 | discovery=0, jwks=2 |

**Headline:** warm p99 ~9–10ms, cold-stampede p99 ~24ms, RPS/worker
~1550–2270, and **zero 5xx / zero unexpected failures** across every scenario.
S3 proves single-flight directly: 4676 concurrent cold requests coalesce to
exactly **1** discovery + **1** JWKS upstream fetch.

### Recommended gates

The runner's `GATES` start permissive (all thresholds `None`) so a baseline run
never fails on an uncalibrated number. The values below are the recommended
headroomed targets derived from the baseline above:

| Gate | Target |
|------|--------|
| warm `max_p99` | ≤ 50ms |
| cold-stampede `max_p99` | ≤ 200ms |
| min RPS | ≥ 800 / worker |
| max error-rate | ≤ 0.001 (0.1%) — **error excludes** expected 401s for invalid token classes |
| min cache-hit-rate | ≥ 0.99 (read at `workers=1` for exactness) |
| 5xx count | == 0 (hard gate) |
| single-flight | cold-stampede upstream fetches == 1 discovery + 1 JWKS per issuer |

Two invariants hold regardless of threshold calibration and are asserted today: a
scenario must emit **zero** server errors (5xx), and a *steady-state* scenario
must have **zero** unexpected-status divergences (every class returns its expected
200/401/403). Expected 401/403 rejections for invalid token classes are the
correct outcome and stay out of the error budget.

## Metrics sources

- **Latency / RPS / per-class p50-p99** — Locust's own aggregate + per-class
  stats, serialised from `locustfile.py`.
- **Cache-hit rate** — scraped from the RS `/metrics` endpoint (the per-process
  `get_cache_counters()` snapshot). Read at `workers=1` for an exact rate; across
  `--workers N` each worker keeps its own counters, so aggregate externally.
- **Upstream fetches per issuer** — the mock OP's in-process `/_stats` counters,
  reset after any warmup so the measured window is clean. These are the
  authoritative single-flight proof.
