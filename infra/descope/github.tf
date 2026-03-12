# Push Descope credentials to GitHub Actions so CI stays in sync
# whenever resources are recreated.

resource "github_actions_secret" "descope_disco_address" {
  repository      = var.github_repository
  secret_name     = "DESCOPE_DISCO_ADDRESS"
  plaintext_value = "https://api.descope.com/${var.project_id}/.well-known/openid-configuration"
}

resource "github_actions_secret" "descope_jwks_address" {
  repository      = var.github_repository
  secret_name     = "DESCOPE_JWKS_ADDRESS"
  plaintext_value = "https://api.descope.com/${var.project_id}/.well-known/jwks.json"
}

resource "github_actions_secret" "descope_client_id" {
  repository      = var.github_repository
  secret_name     = "DESCOPE_CLIENT_ID"
  plaintext_value = descope_access_key.m2m.client_id
}

resource "github_actions_secret" "descope_client_secret" {
  repository      = var.github_repository
  secret_name     = "DESCOPE_CLIENT_SECRET"
  plaintext_value = descope_access_key.m2m.cleartext
}

resource "github_actions_secret" "descope_scope" {
  repository      = var.github_repository
  secret_name     = "DESCOPE_SCOPE"
  plaintext_value = "openid"
}

resource "github_actions_secret" "descope_audience" {
  repository      = var.github_repository
  secret_name     = "DESCOPE_AUDIENCE"
  plaintext_value = var.project_id
}

# Generate an expired access-key token for negative test cases.
# The project's access_key_session_token_expiration is 3 minutes,
# so any token created here will be expired by the time CI runs.
resource "terraform_data" "expired_token" {
  triggers_replace = [
    descope_access_key.m2m.client_id,
    descope_access_key.m2m.cleartext,
  ]

  provisioner "local-exec" {
    command = <<-EOT
      TOKEN=$(curl -s -X POST https://api.descope.com/v1/auth/accesskey/exchange \
        -H "Authorization: Bearer ${var.project_id}:${descope_access_key.m2m.cleartext}" \
        -H "Content-Type: application/json" \
        -d '{"loginId": "${descope_access_key.m2m.client_id}"}' \
        | python3 -c "import sys,json; print(json.load(sys.stdin).get('sessionJwt',''))")

      echo "$TOKEN" > ${path.module}/expired_token.txt
    EOT
  }
}

data "local_file" "expired_token" {
  depends_on = [terraform_data.expired_token]
  filename   = "${path.module}/expired_token.txt"
}

resource "github_actions_secret" "descope_expired_token" {
  repository      = var.github_repository
  secret_name     = "DESCOPE_EXPIRED_TOKEN"
  plaintext_value = trimspace(data.local_file.expired_token.content)
}
