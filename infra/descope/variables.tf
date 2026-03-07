variable "descope_management_key" {
  type        = string
  sensitive   = true
  description = "Descope management key from Company settings. Set via DESCOPE_MANAGEMENT_KEY env var."
}

variable "project_name" {
  type        = string
  default     = "py-identity-model-test"
  description = "Name for the Descope project"
}
