variable "project_id" {
  type        = string
  description = "Shared Descope project ID (from descope-saas-starter). Used as audience and in discovery URLs."
}

variable "github_repository" {
  type        = string
  default     = "py-identity-model"
  description = "GitHub repository name (without owner) for CI secrets"
}
