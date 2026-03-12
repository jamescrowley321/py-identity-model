output "project_id" {
  value       = var.project_id
  description = "Descope project ID (used as audience and in discovery URL)"
}

output "discovery_url" {
  value       = "https://api.descope.com/${var.project_id}/.well-known/openid-configuration"
  description = "OIDC discovery endpoint"
}

output "jwks_url" {
  value       = "https://api.descope.com/${var.project_id}/.well-known/jwks.json"
  description = "JWKS endpoint"
}

output "client_id" {
  value       = descope_access_key.m2m.client_id
  description = "M2M access key client ID"
}

output "client_secret" {
  value       = descope_access_key.m2m.cleartext
  sensitive   = true
  description = "M2M access key secret (only available at creation time)"
}
