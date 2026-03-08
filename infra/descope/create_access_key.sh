#!/usr/bin/env bash
set -euo pipefail

# Called by Terraform local-exec to create an M2M access key via the Descope Management API.
# Inputs (env vars): PROJECT_ID, MANAGEMENT_KEY, ACCESS_KEY_NAME
# Output: writes access_key.json with clientId and cleartext

PROJECT_ID="${PROJECT_ID:?PROJECT_ID is required}"
MANAGEMENT_KEY="${MANAGEMENT_KEY:?MANAGEMENT_KEY is required}"
ACCESS_KEY_NAME="${ACCESS_KEY_NAME:-py-identity-model-m2m}"
OUTPUT_FILE="${OUTPUT_FILE:-access_key.json}"

BEARER_TOKEN="${PROJECT_ID}:${MANAGEMENT_KEY}"

json_payload=$(jq -n --arg name "$ACCESS_KEY_NAME" '{
  name: $name,
  roleNames: ["admin"],
  description: "M2M access key for py-identity-model integration tests"
}')

response=$(curl -sf -X POST "https://api.descope.com/v1/mgmt/accesskey/create" \
  -H "Authorization: Bearer ${BEARER_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "$json_payload")

client_id=$(echo "$response" | jq -r '.key.clientId')
cleartext=$(echo "$response" | jq -r '.cleartext')

jq -n --arg id "$client_id" --arg secret "$cleartext" \
  '{client_id: $id, client_secret: $secret}' > "$OUTPUT_FILE"

echo "Access key created: client_id=${client_id}"
