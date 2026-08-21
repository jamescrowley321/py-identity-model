"""Load / soak suite for the token-blaster harness (TH-1.5, #474, epic #462).

Drives the booted resource server (:func:`~tests.harness.rs_server.boot_rs`) with
the pre-minted replay pool and the controllable mock OP
(:func:`~tests.harness.serve_mock_op`) under Locust, implementing design §4's
scenarios S1-S12 and reporting the §5 metrics (RPS, latency percentiles,
error-rate-by-class, cache-hit-rate, upstream fetches/issuer).

* :mod:`scenarios` — the S1-S12 catalogue + run profiles + expected-status map.
* :mod:`pool` — the pre-minted replay pool (mint once, replay many).
* :mod:`locustfile` — a standalone Locust file the runner drives as a subprocess.
* :mod:`runner` — orchestration (fresh mock OP + booted RS per scenario) + metric
  collection + SLO gates.

``locust`` is a ``load`` dependency-group extra. Importing it triggers gevent's
``monkey.patch_all()``, which deadlocks the parent's in-process asyncio mock-OP
server thread, so :mod:`runner` runs Locust OUT of process (never importing it)
and :mod:`locustfile` — the only module that imports ``locust`` — runs only in
that subprocess. Both are excluded from the root pyrefly lint env; run the suite
via ``make test-harness-load``.
"""
