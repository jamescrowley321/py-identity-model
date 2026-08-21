#!/bin/sh
client=$(hydra create client \
    --endpoint http://127.0.0.1:4445/ \
    --format json \
    --grant-type client_credentials)

# We parse the JSON response using jq to get the client ID and client secret:
client_id=$(echo "$client" | jq -r '.client_id')
client_secret=$(echo "$client" | jq -r '.client_secret')


hydra perform client-credentials --endpoint http://127.0.0.1:4444/ \
  --client-id "$client_id" \
  --client-secret "$client_secret" \
  -- audience https://py-identity-model
  --format json
