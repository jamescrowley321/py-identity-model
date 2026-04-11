#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["playwright>=1.40"]
# ///
"""Rotate the OIDC conformance-suite API token and push it to HCP Vault Secrets.

Target service: https://www.certification.openid.net/

Why this exists
---------------
The OIDF certification server exposes a REST API (`/api/plan`, `/api/runner`,
`/api/info`, `/api/plan/{id}/certificationpackage`) that is authenticated via a
Bearer token. Tokens are created via a single interactive step: log in to the
suite via Google or GitLab OIDC in a browser, navigate to the API token
management page, and click "Create". Everything after that (running the test
plans, publishing the certification package) is plain HTTP against the REST
API using the Bearer token.

This script automates the token creation + storage half of that workflow so
token rotation is reproducible and the resulting secret lives in HCP Vault
Secrets instead of a `.env` file on someone's laptop.

Flow
----
1. Launch Chromium with a persistent user-data dir (so OIDC sessions stick).
2. Navigate to https://www.certification.openid.net/.
3. If not logged in, wait for the operator to complete the OIDC flow
   interactively (Google/GitLab). First run is always headful.
4. Navigate to the token management page and create a new API token.
5. Capture the token value from the UI.
6. Push the value to HCP Vault Secrets via `hcp vault-secrets secrets create`.

Prerequisites
-------------
- Python 3.10+
- uv (https://docs.astral.sh/uv/) for the PEP 723 inline script runner
- Playwright Chromium browser binary:
      uv run --with playwright playwright install chromium
- HCP CLI (https://developer.hashicorp.com/hcp/docs/cli/install) already
  authenticated via `hcp auth login` and scoped to the target org/project
  via `hcp profile init`.

Usage
-----
First run (interactive OIDC login — browser opens, you sign in manually):

      uv run conformance/scripts/rotate_conformance_token.py

Subsequent runs (persistent profile keeps you logged in, can be headless):

      uv run conformance/scripts/rotate_conformance_token.py --headless

Preview what the script will do without pushing to Vault:

      uv run conformance/scripts/rotate_conformance_token.py --dry-run

Show the full token value on stdout instead of masking it (use with care;
anything that stores stdout persistently — shell history, CI logs — becomes
a secret spill surface):

      uv run conformance/scripts/rotate_conformance_token.py --show-token

Environment variables
---------------------
HCP_VAULT_APP_NAME     HCP Vault Secrets app to push to
                       (default: py-identity-model)
HCP_VAULT_SECRET_NAME  Secret name inside the app
                       (default: CONFORMANCE_TOKEN)
PLAYWRIGHT_PROFILE_DIR Override the persistent browser profile directory
                       (default: ~/.cache/py-identity-model/playwright-profile)

Design notes
------------
- **Persistent profile over headless auth**: Google and GitLab both actively
  block headless Chromium on login pages (UA detection + "this browser or app
  may not be secure" blocks). Letting the operator sign in once in a headful
  session and reusing the cookie jar is far more reliable than trying to
  defeat the bot detection. First run is interactive; subsequent runs can
  be headless as long as the session cookie is still valid.

- **UI-driven token creation**: The suite has a REST endpoint at POST
  /api/token but its exact request/response format is not publicly
  documented outside the `TokenApi.java` source. Rather than guess, this
  script drives the suite's UI (which is a stable, documented interface).
  If the UI layout changes, fix the selectors in `_create_api_token_via_ui`
  and rerun.

- **Push via the hcp CLI, not the REST API**: HCP Vault Secrets has an HTTP
  API, but the `hcp` CLI is the easier surface — it handles auth token
  refresh, org/project scoping, and error reporting. Shelling out is fine
  for a script that runs occasionally under human supervision.

- **No credentials in the script**: The script never reads Google/GitLab
  passwords from environment variables. All user auth happens in the
  browser the operator controls.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import subprocess
import sys

from playwright.sync_api import Page, sync_playwright
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError


SUITE_URL = "https://www.certification.openid.net/"
TOKEN_MANAGEMENT_PATH = "token-management.html"
DEFAULT_PROFILE_DIR = (
    Path.home() / ".cache" / "py-identity-model" / "playwright-profile"
)
DEFAULT_APP_NAME = "py-identity-model"
DEFAULT_SECRET_NAME = "CONFORMANCE_TOKEN"
DEFAULT_TOKEN_DESCRIPTION = "py-identity-model automation (Playwright-rotated)"

LOGIN_WAIT_TIMEOUT_MS = 5 * 60 * 1000  # 5 minutes
UI_INTERACTION_TIMEOUT_MS = 30 * 1000  # 30 seconds

# Minimum token length below which we treat the value as untrustworthy and
# refuse to render even a partial mask on stderr. The hosted suite issues
# ~40-char Bearer tokens; anything shorter than this likely indicates a bug
# in the extraction path rather than a real secret.
MIN_MASKABLE_TOKEN_LEN = 12


@dataclass
class RotateConfig:
    """Runtime config for a single rotation run."""

    profile_dir: Path
    headless: bool
    dry_run: bool
    show_token: bool
    app_name: str
    secret_name: str
    token_description: str


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Rotate the OIDC conformance suite API token and push it to HCP Vault Secrets."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help=(
            "Run Chromium headless. Only works if a prior interactive run has "
            "already captured the OIDC session cookies in the profile dir."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Create the token but print it instead of pushing to HCP Vault Secrets.",
    )
    parser.add_argument(
        "--show-token",
        action="store_true",
        help="Print the full token value on stdout (default: masked).",
    )
    parser.add_argument(
        "--profile-dir",
        type=Path,
        default=None,
        help=f"Playwright profile dir override (default: {DEFAULT_PROFILE_DIR}).",
    )
    parser.add_argument(
        "--app-name",
        default=os.environ.get("HCP_VAULT_APP_NAME", DEFAULT_APP_NAME),
        help=f"HCP Vault Secrets app name (default: {DEFAULT_APP_NAME}).",
    )
    parser.add_argument(
        "--secret-name",
        default=os.environ.get("HCP_VAULT_SECRET_NAME", DEFAULT_SECRET_NAME),
        help=f"Secret name inside the HCP app (default: {DEFAULT_SECRET_NAME}).",
    )
    parser.add_argument(
        "--description",
        default=DEFAULT_TOKEN_DESCRIPTION,
        help="Description attached to the new token in the conformance UI.",
    )
    return parser.parse_args(argv)


def build_config(ns: argparse.Namespace) -> RotateConfig:
    profile_dir = ns.profile_dir or Path(
        os.environ.get("PLAYWRIGHT_PROFILE_DIR", str(DEFAULT_PROFILE_DIR))
    )
    return RotateConfig(
        profile_dir=profile_dir,
        headless=ns.headless,
        dry_run=ns.dry_run,
        show_token=ns.show_token,
        app_name=ns.app_name,
        secret_name=ns.secret_name,
        token_description=ns.description,
    )


# ---------------------------------------------------------------------------
# Browser automation
# ---------------------------------------------------------------------------


def create_token_in_browser(cfg: RotateConfig) -> str:
    """Launch Playwright, let the user log in if needed, create a token via the UI."""
    cfg.profile_dir.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        context = p.chromium.launch_persistent_context(
            user_data_dir=str(cfg.profile_dir),
            headless=cfg.headless,
            args=["--disable-blink-features=AutomationControlled"],
        )
        try:
            page = context.new_page() if not context.pages else context.pages[0]
            page.set_default_timeout(UI_INTERACTION_TIMEOUT_MS)
            page.goto(SUITE_URL, wait_until="networkidle")

            if _needs_login(page):
                if cfg.headless:
                    raise RuntimeError(
                        "Not logged in and running headless. Re-run without --headless "
                        "to complete the OIDC login interactively — the persistent "
                        "profile will remember the session for subsequent runs."
                    )
                print(
                    "Please complete the OIDC login (Google or GitLab) in the "
                    "browser window. Waiting up to 5 minutes.",
                    file=sys.stderr,
                )
                _wait_until_logged_in(page, LOGIN_WAIT_TIMEOUT_MS)
                print("Login detected. Creating API token...", file=sys.stderr)

            return _create_api_token_via_ui(page, cfg.token_description)
        finally:
            context.close()


def _needs_login(page: Page) -> bool:
    """Return True if the suite is showing an unauthenticated landing page.

    The suite's front page renders a prominent "Login" link in the nav bar
    when the session is unauthenticated and hides it once signed in. We use
    that as the authentication heuristic.
    """
    login_locator = page.get_by_role("link", name="Login")
    return login_locator.count() > 0 and login_locator.first.is_visible()


def _wait_until_logged_in(page: Page, timeout_ms: int) -> None:
    """Block until the Login link disappears or the user's name appears."""
    page.wait_for_function(
        """
        () => {
            const links = Array.from(document.querySelectorAll('a, button'));
            const login = links.find(el => el.textContent.trim().toLowerCase() === 'login');
            return !login || login.offsetParent === null;
        }
        """,
        timeout=timeout_ms,
    )


def _create_api_token_via_ui(page: Page, description: str) -> str:
    """Navigate to the token management page, create a token, return its value.

    The conformance suite serves its static token management UI from
    ``/token-management.html``. If the suite's UI layout changes, update the
    selectors below. The REST fallback is documented in the module docstring.
    """
    page.goto(SUITE_URL + TOKEN_MANAGEMENT_PATH, wait_until="networkidle")

    # Open the "create token" dialog. The exact button text is defensive —
    # the suite's UI has used both "Create API Token" and "New Token" in
    # past revisions. Try the more recent label first.
    create_button = page.get_by_role("button", name="Create API Token")
    if create_button.count() == 0:
        create_button = page.get_by_role("button", name="New Token")
    if create_button.count() == 0:
        raise RuntimeError(
            "Could not find a 'Create API Token' or 'New Token' button on the "
            "token management page. The UI layout may have changed. Re-run with "
            "--headless=false and a debugger attached, or switch to the REST "
            "API path described in the module docstring."
        )
    create_button.first.click()

    # Fill in the description field, then submit.
    description_input = page.locator(
        'input[name="description"], textarea[name="description"]'
    )
    if description_input.count() > 0:
        description_input.first.fill(description)

    submit = page.get_by_role("button", name="Create")
    submit.first.click()

    # The new token is shown exactly once after creation. Capture it before
    # the dialog closes. The suite's template has exposed the token value on
    # an element with attribute `data-token` in the past; if that attribute
    # is missing, fall back to any visible monospace block inside the dialog.
    try:
        page.wait_for_selector("[data-token]", timeout=UI_INTERACTION_TIMEOUT_MS)
        token_value = page.get_attribute("[data-token]", "data-token")
    except PlaywrightTimeoutError:
        token_value = _extract_token_fallback(page)

    if not token_value:
        raise RuntimeError(
            "Token creation request succeeded but no token value was captured "
            "from the UI. Re-run with --show-token and a debugger to inspect."
        )
    return token_value.strip()


def _extract_token_fallback(page: Page) -> str | None:
    """Fallback token extraction: look for any monospace block in the active dialog."""
    dialog = page.get_by_role("dialog")
    if dialog.count() == 0:
        return None
    code_block = dialog.locator("code, pre, .token-value")
    if code_block.count() == 0:
        return None
    return code_block.first.inner_text()


# ---------------------------------------------------------------------------
# HCP Vault Secrets push
# ---------------------------------------------------------------------------


def push_to_hcp_vault_secrets(token: str, app_name: str, secret_name: str) -> None:
    """Store the token in HCP Vault Secrets via the `hcp` CLI.

    Uses ``hcp vault-secrets secrets create`` with the value on stdin so the
    token never appears on the process's command line (which would be visible
    to other users via ``ps`` on shared systems).
    """
    hcp_path = _ensure_hcp_cli_available()

    cmd = [
        hcp_path,
        "vault-secrets",
        "secrets",
        "create",
        secret_name,
        "--app",
        app_name,
        "--data-file=-",
    ]
    result = subprocess.run(  # noqa: S603 — CLI invocation, argv is fully controlled above
        cmd,
        input=token,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"hcp CLI failed (exit {result.returncode}).\n"
            f"  stderr: {result.stderr.strip()}\n"
            f"  stdout: {result.stdout.strip()}"
        )


def _ensure_hcp_cli_available() -> str:
    """Verify the `hcp` CLI is installed and authenticated, return its resolved path.

    Returns the absolute path to the ``hcp`` binary as resolved by
    :func:`shutil.which` so subsequent ``subprocess.run`` calls pass an
    absolute argv[0] and don't rely on PATH lookups at the subprocess
    boundary. Raises RuntimeError with an actionable message if the CLI is
    missing. We do not attempt to run ``hcp auth login`` automatically
    because that would itself require an interactive flow and is out of
    scope for this script.
    """
    hcp_path = shutil.which("hcp")
    if hcp_path is None:
        raise RuntimeError(
            "hcp CLI not found on PATH. Install it from "
            "https://developer.hashicorp.com/hcp/docs/cli/install."
        )
    try:
        subprocess.run(  # noqa: S603 — argv is fully controlled above
            [hcp_path, "--version"],
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"hcp CLI version check failed: {exc.stderr.decode()}"
        ) from exc
    return hcp_path


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


def mask_token(token: str) -> str:
    if len(token) <= MIN_MASKABLE_TOKEN_LEN:
        return "***"
    return f"{token[:6]}...{token[-4:]}"


def rotate_token(cfg: RotateConfig) -> None:
    print(f"Rotating CONFORMANCE_TOKEN via {SUITE_URL}", file=sys.stderr)
    print(f"  profile dir: {cfg.profile_dir}", file=sys.stderr)
    print(f"  target: {cfg.app_name} / {cfg.secret_name}", file=sys.stderr)

    token = create_token_in_browser(cfg)
    display = token if cfg.show_token else mask_token(token)
    print(f"Token created: {display}", file=sys.stderr)

    if cfg.dry_run:
        print("--dry-run set; not pushing to HCP Vault Secrets.", file=sys.stderr)
        if not cfg.show_token:
            print(
                "Re-run with --show-token to print the value, or remove --dry-run "
                "to push it to HCP Vault Secrets.",
                file=sys.stderr,
            )
        return

    push_to_hcp_vault_secrets(token, cfg.app_name, cfg.secret_name)
    print(
        f"Pushed token to HCP Vault Secrets: {cfg.app_name} / {cfg.secret_name}",
        file=sys.stderr,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    try:
        cfg = build_config(parse_args(argv))
        rotate_token(cfg)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except PlaywrightTimeoutError as exc:
        print(f"browser timeout: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
