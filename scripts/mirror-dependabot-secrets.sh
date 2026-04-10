#!/usr/bin/env bash
#
# Mirror the repo secrets that CI references into the Dependabot secret scope
# so dependabot-authored PRs can run the full CI matrix (lint, unit tests,
# both integration suites, sonarcloud). Run this once per repo; re-run when
# a secret value rotates or a new one is added to CI.
#
# GitHub does not let any principal read an existing secret value, so this
# script reads the required values from your current shell environment. The
# easiest way to populate the shell is:
#
#     source .env          # Ory / local fixture values (TEST_*)
#     source .env.descope  # Descope values — but rename the variables first
#                          # because .env.descope uses TEST_* names, not DESCOPE_*
#
# Alternatively, export each variable by hand or pull from a secret store.
#
# Usage:
#   ./scripts/mirror-dependabot-secrets.sh
#
# Requires: `gh` authenticated as a repo admin on the target repo.

set -euo pipefail

REPO="${REPO:-jamescrowley321/py-identity-model}"

SECRETS=(
  TEST_DISCO_ADDRESS
  TEST_JWKS_ADDRESS
  TEST_CLIENT_ID
  TEST_CLIENT_SECRET
  TEST_SCOPE
  TEST_EXPIRED_TOKEN
  TEST_AUDIENCE
  DESCOPE_DISCO_ADDRESS
  DESCOPE_JWKS_ADDRESS
  DESCOPE_CLIENT_ID
  DESCOPE_CLIENT_SECRET
  DESCOPE_SCOPE
  DESCOPE_EXPIRED_TOKEN
  DESCOPE_AUDIENCE
  SONAR_TOKEN
)

missing=()
for name in "${SECRETS[@]}"; do
  if [[ -z "${!name:-}" ]]; then
    missing+=("$name")
  fi
done

if (( ${#missing[@]} > 0 )); then
  printf 'ERROR: the following env vars are not set in the current shell:\n' >&2
  printf '  %s\n' "${missing[@]}" >&2
  printf '\nExport them (e.g. `source .env`) then re-run this script.\n' >&2
  exit 1
fi

printf 'Mirroring %d secrets to Dependabot scope on %s...\n' "${#SECRETS[@]}" "$REPO"
for name in "${SECRETS[@]}"; do
  printf '%s' "${!name}" | gh secret set "$name" --app dependabot --repo "$REPO"
  printf '  set %s\n' "$name"
done

printf '\nDone. Verify with:\n  gh api repos/%s/dependabot/secrets\n' "$REPO"
