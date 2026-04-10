#!/usr/bin/env python3
"""OIDF conformance suite test runner.

Automates test plan creation and execution against the OpenID Foundation
conformance suite, driving the RP harness through each test module.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import logging
from pathlib import Path
import sys
import time

import httpx


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
)
logger = logging.getLogger("conformance-runner")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SUITE_BASE_URL = "https://localhost.emobix.co.uk:8443"
RP_BASE_URL = "http://localhost:8888"
POLL_INTERVAL = 2  # seconds
MAX_POLL_ATTEMPTS = 60  # 2 minutes max per test


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class TestResult:
    """Result of a single conformance test module."""

    test_name: str
    test_id: str
    status: str  # PASSED, WARNING, FAILED, REVIEW, SKIPPED, INTERRUPTED
    log_url: str = ""
    detail: str = ""


# ---------------------------------------------------------------------------
# Suite API client
# ---------------------------------------------------------------------------


class ConformanceSuiteClient:
    """REST API client for the OIDF conformance suite."""

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.client = httpx.Client(verify=False, timeout=30.0)

    def create_plan(
        self, plan_name: str, variant: dict, alias: str, rp_base_url: str = RP_BASE_URL
    ) -> dict:
        """Create a test plan.

        Returns the plan response including plan ID and list of test modules.
        """
        # Build the plan configuration
        plan_config = {
            "alias": alias,
            "description": f"py-identity-model conformance: {alias}",
            "publish": "",
            "server": {
                "discoveryUrl": "",
            },
            "client": {
                "client_id": "conformance-rp",
                "client_secret": "conformance-rp-secret",
                "redirect_uri": f"{rp_base_url}/callback",
            },
            "client2": {
                "client_id": "conformance-rp-2",
                "client_secret": "conformance-rp-2-secret",
            },
        }

        # Variant is a single JSON-encoded query parameter (per official conformance.py)
        params: dict[str, str] = {"planName": plan_name}
        if variant:
            params["variant"] = json.dumps(variant)

        response = self.client.post(
            f"{self.base_url}/api/plan",
            params=params,
            json=plan_config,
        )
        response.raise_for_status()
        return response.json()

    def create_test_module(self, test_name: str, plan_id: str) -> dict:
        """Create a test module instance within a plan."""
        response = self.client.post(
            f"{self.base_url}/api/runner",
            params={"test": test_name, "plan": plan_id},
        )
        response.raise_for_status()
        return response.json()

    def start_test(self, module_id: str) -> None:
        """Start a test module."""
        response = self.client.post(
            f"{self.base_url}/api/runner/{module_id}",
        )
        response.raise_for_status()

    def get_test_info(self, module_id: str) -> dict:
        """Get current status of a test module."""
        response = self.client.get(
            f"{self.base_url}/api/info/{module_id}",
        )
        response.raise_for_status()
        return response.json()

    def get_test_log(self, module_id: str) -> list:
        """Get detailed log entries for a test module."""
        response = self.client.get(
            f"{self.base_url}/api/log/{module_id}",
        )
        response.raise_for_status()
        return response.json()

    def poll_until_done(self, module_id: str) -> dict:
        """Poll a test module until it reaches a terminal state."""
        for _ in range(MAX_POLL_ATTEMPTS):
            info = self.get_test_info(module_id)
            status = info.get("status", "UNKNOWN")
            if status in ("FINISHED", "INTERRUPTED"):
                return info
            logger.debug("Test %s status: %s", module_id, status)
            time.sleep(POLL_INTERVAL)
        return {"status": "TIMEOUT", "id": module_id}


# ---------------------------------------------------------------------------
# RP driver
# ---------------------------------------------------------------------------


def drive_rp_authorize(
    rp_base_url: str,
    issuer: str,
    client_id: str,
    client_secret: str,
    test_id: str,
    use_pkce: bool = False,
) -> None:
    """Hit the RP's /authorize endpoint to start an auth flow.

    The RP will redirect to the conformance suite's OP, which handles
    the entire flow and redirects back to /callback. We just need to
    follow the redirects.
    """
    params = {
        "issuer": issuer,
        "client_id": client_id,
        "client_secret": client_secret,
        "test_id": test_id,
        "use_pkce": str(use_pkce).lower(),
    }

    # Follow all redirects through the full auth flow
    with httpx.Client(verify=False, timeout=30.0, follow_redirects=True) as client:
        try:
            response = client.get(f"{rp_base_url}/authorize", params=params)
            logger.info(
                "RP flow completed: status=%d, url=%s",
                response.status_code,
                response.url,
            )
        except httpx.HTTPError as exc:
            logger.warning("RP flow HTTP error (may be expected): %s", exc)


# ---------------------------------------------------------------------------
# Test execution
# ---------------------------------------------------------------------------


def run_test_module(
    suite: ConformanceSuiteClient,
    test_name: str,
    plan_id: str,
    rp_base_url: str,
    client_id: str,
    client_secret: str,
) -> TestResult:
    """Execute a single conformance test module."""
    logger.info("=" * 60)
    logger.info("Running test: %s", test_name)
    logger.info("=" * 60)

    # Create the test module instance
    try:
        module_info = suite.create_test_module(test_name, plan_id)
    except httpx.HTTPStatusError as exc:
        logger.error("Failed to create test module %s: %s", test_name, exc)
        return TestResult(
            test_name=test_name,
            test_id="",
            status="FAILED",
            detail=f"Failed to create test module: {exc}",
        )

    module_id: str = module_info.get("id", module_info.get("name", "")) or ""
    logger.info("Test module created: %s", module_id)

    # Start the test
    try:
        suite.start_test(module_id)
    except httpx.HTTPStatusError as exc:
        logger.error("Failed to start test %s: %s", test_name, exc)
        return TestResult(
            test_name=test_name,
            test_id=module_id,
            status="FAILED",
            detail=f"Failed to start test: {exc}",
        )

    logger.info("Test started, driving RP authorize flow...")

    # Get test info to find the issuer
    try:
        info = suite.get_test_info(module_id)
        # The conformance suite exposes dynamic issuer in the test config
        issuer = info.get("config", {}).get("server", {}).get("discoveryUrl", "")
        if not issuer:
            # Fallback: construct from test module ID
            issuer = f"{suite.base_url}/test/a/py-identity-model/{module_id}"
    except httpx.HTTPStatusError:
        issuer = f"{suite.base_url}/test/a/py-identity-model/{module_id}"

    # Drive the RP through the authorization flow
    drive_rp_authorize(
        rp_base_url=rp_base_url,
        issuer=issuer,
        client_id=client_id,
        client_secret=client_secret,
        test_id=module_id,
    )

    # Poll until the test finishes
    logger.info("Polling test status...")
    result_info = suite.poll_until_done(module_id)
    status = result_info.get("status", "UNKNOWN")
    result = result_info.get("result", status)

    # Map status to final result
    final_status = (result if result else "PASSED") if status == "FINISHED" else status

    log_url = f"{suite.base_url}/log-detail.html?log={module_id}"
    detail = ""

    # Fetch logs for failed tests
    if final_status in ("FAILED", "WARNING", "REVIEW"):
        try:
            logs = suite.get_test_log(module_id)
            # Extract failure messages
            failures = [
                entry
                for entry in logs
                if entry.get("result", "") in ("FAILURE", "WARNING")
            ]
            if failures:
                detail = "; ".join(
                    f"{f.get('src', '')}: {f.get('msg', '')}" for f in failures[:5]
                )
        except httpx.HTTPStatusError:
            pass

    log_symbol = {
        "PASSED": "PASS",
        "WARNING": "WARN",
        "FAILED": "FAIL",
        "REVIEW": "REVIEW",
        "SKIPPED": "SKIP",
    }.get(final_status, "????")
    logger.info("[%s] %s — %s", log_symbol, test_name, log_url)
    if detail:
        logger.info("  Detail: %s", detail)

    return TestResult(
        test_name=test_name,
        test_id=module_id,
        status=final_status,
        log_url=log_url,
        detail=detail,
    )


def run_plan(
    config_path: str,
    suite_base_url: str = SUITE_BASE_URL,
    rp_base_url: str = RP_BASE_URL,
) -> list[TestResult]:
    """Run all tests in a conformance test plan."""
    # Load plan config
    config = json.loads(Path(config_path).read_text())
    plan_name = config["plan_name"]
    variant = config["variant"]
    alias = config["alias"]

    logger.info("Plan: %s (%s)", plan_name, alias)
    logger.info("Variant: %s", variant)
    logger.info("Suite: %s", suite_base_url)
    logger.info("RP: %s", rp_base_url)

    suite = ConformanceSuiteClient(suite_base_url)

    # Create the test plan
    logger.info("Creating test plan...")
    plan_response = suite.create_plan(
        plan_name, variant, alias, rp_base_url=rp_base_url
    )
    plan_id = plan_response.get("id", "")
    modules = plan_response.get("modules", [])

    if not plan_id:
        logger.error("Failed to create plan: %s", plan_response)
        sys.exit(1)

    logger.info("Plan created: %s with %d test modules", plan_id, len(modules))

    # Extract test names from modules
    test_names = []
    for module in modules:
        if isinstance(module, dict):
            test_names.append(module.get("testModule", ""))
        else:
            test_names.append(str(module))

    if not test_names:
        logger.error("No test modules found in plan")
        sys.exit(1)

    logger.info("Tests to run: %s", ", ".join(test_names))

    # Client credentials from plan config
    client_id = "conformance-rp"
    client_secret = "conformance-rp-secret"

    # Run each test
    results: list[TestResult] = []
    for test_name in test_names:
        result = run_test_module(
            suite=suite,
            test_name=test_name,
            plan_id=plan_id,
            rp_base_url=rp_base_url,
            client_id=client_id,
            client_secret=client_secret,
        )
        results.append(result)

    return results


def print_summary(results: list[TestResult]) -> bool:
    """Print a summary table and return True if all passed/warned."""
    print("\n" + "=" * 70)
    print("CONFORMANCE TEST RESULTS")
    print("=" * 70)
    print(f"{'Test':<50} {'Result':<10}")
    print("-" * 70)

    all_ok = True
    for r in results:
        symbol = {
            "PASSED": "PASS",
            "WARNING": "WARN",
            "FAILED": "FAIL",
            "REVIEW": "REVIEW",
            "SKIPPED": "SKIP",
        }.get(r.status, "????")
        print(f"{r.test_name:<50} [{symbol}]")
        if r.detail:
            print(f"  {r.detail}")
        if r.status in ("FAILED", "INTERRUPTED", "TIMEOUT"):
            all_ok = False

    print("-" * 70)
    passed = sum(1 for r in results if r.status == "PASSED")
    warned = sum(1 for r in results if r.status == "WARNING")
    failed = sum(1 for r in results if r.status in ("FAILED", "INTERRUPTED", "TIMEOUT"))
    skipped = sum(1 for r in results if r.status == "SKIPPED")
    review = sum(1 for r in results if r.status == "REVIEW")
    print(
        f"Total: {len(results)} | Passed: {passed} | Warnings: {warned} | "
        f"Failed: {failed} | Review: {review} | Skipped: {skipped}"
    )
    print("=" * 70)

    return all_ok


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run OIDF conformance tests against py-identity-model"
    )
    parser.add_argument(
        "--plan",
        required=True,
        choices=["basic-rp", "config-rp"],
        help="Test plan to run",
    )
    parser.add_argument(
        "--suite-url",
        default=SUITE_BASE_URL,
        help=f"Conformance suite base URL (default: {SUITE_BASE_URL})",
    )
    parser.add_argument(
        "--rp-url",
        default=RP_BASE_URL,
        help=f"RP harness base URL (default: {RP_BASE_URL})",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable debug logging",
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    config_path = Path(__file__).parent / "configs" / f"{args.plan}.json"
    if not config_path.exists():
        logger.error("Config not found: %s", config_path)
        sys.exit(1)

    results = run_plan(
        config_path=str(config_path),
        suite_base_url=args.suite_url,
        rp_base_url=args.rp_url,
    )

    all_ok = print_summary(results)
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
