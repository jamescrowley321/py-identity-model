# tests
Due to the nature of the library, the tests are written as integration tests against a live OIDC provider.
# Environment Configuration
```shell
touch .env

TEST_DISCO_ADDRESS=
TEST_JWKS_ADDRESS=
TEST_CLIENT_ID=
TEST_CLIENT_SECRET=
TEST_EXPIRED_TOKEN=
TEST_AUDIENCE=
TEST_SCOPE=
```

```shell
export $(cat .env | xargs)
```

```shell
client=$(hydra \
    hydra create client \
    --endpoint http://127.0.0.1:4445/ \
    --format json \
    --grant-type client_credentials)

# We parse the JSON response using jq to get the client ID and client secret:
client_id=$(echo $client | jq -r '.client_id')
client_secret=$(echo $client | jq -r '.client_secret')

hydra \
  hydra perform client-credentials \
  --endpoint http://127.0.0.1:4444/ \
  --client-id "$client_id" \
  --client-secret "$client_secret"
```