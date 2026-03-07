output "project_id" {
  value       = descope_project.py_identity_model.id
  description = "Descope project ID (used as audience and in discovery URL)"
}

output "discovery_url" {
  value       = "https://api.descope.com/${descope_project.py_identity_model.id}/.well-known/openid-configuration"
  description = "OIDC discovery endpoint"
}

output "jwks_url" {
  value       = "https://api.descope.com/${descope_project.py_identity_model.id}/.well-known/jwks.json"
  description = "JWKS endpoint"
}

output "client_id" {
  value       = local.access_key.client_id
  description = "M2M access key client ID"
}

output "client_secret" {
  value       = local.access_key.client_secret
  sensitive   = true
  description = "M2M access key secret (only available at creation time)"
}
