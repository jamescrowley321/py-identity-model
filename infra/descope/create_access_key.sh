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

response=$(curl -sf -X POST "https://api.descope.com/v1/mgmt/accesskey/create" \
  -H "Authorization: Bearer ${BEARER_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"${ACCESS_KEY_NAME}\",
    \"roleNames\": [\"admin\"],
    \"description\": \"M2M access key for py-identity-model integration tests\"
  }")

client_id=$(echo "$response" | python3 -c "import sys,json; print(json.load(sys.stdin)['key']['clientId'])")
cleartext=$(echo "$response" | python3 -c "import sys,json; print(json.load(sys.stdin)['cleartext'])")

cat > "$OUTPUT_FILE" <<EOF
{
  "client_id": "${client_id}",
  "client_secret": "${cleartext}"
}
EOF

echo "Access key created: client_id=${client_id}"
