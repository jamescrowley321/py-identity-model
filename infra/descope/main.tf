terraform {
  required_version = ">= 1.5"

  required_providers {
    descope = {
      source  = "descope/descope"
      version = "~> 0.3"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.5"
    }
  }
}

provider "descope" {
  management_key = var.descope_management_key
}

resource "descope_project" "py_identity_model" {
  name = var.project_name

  project_settings = {
    access_key_session_token_expiration = "3 minutes"
  }

  authorization = {
    permissions = [
      { name = "users.create", description = "Create users" },
      { name = "users.read", description = "Read users" },
      { name = "users.delete", description = "Delete users" },
    ]
    roles = [
      {
        name        = "admin"
        key         = "admin"
        description = "Full administrative access"
        permissions = ["users.create", "users.read", "users.delete"]
      },
      {
        name        = "viewer"
        key         = "viewer"
        description = "Read-only access"
        permissions = ["users.read"]
      },
    ]
  }
}

# Create an M2M access key via the Management API.
# The Terraform provider doesn't support access key resources,
# so we use a script that calls the REST API directly.
resource "terraform_data" "access_key" {
  depends_on = [descope_project.py_identity_model]

  provisioner "local-exec" {
    command     = "${path.module}/create_access_key.sh"
    working_dir = path.module
    environment = {
      PROJECT_ID      = descope_project.py_identity_model.id
      MANAGEMENT_KEY  = var.descope_management_key
      ACCESS_KEY_NAME = "py-identity-model-m2m"
      OUTPUT_FILE     = "${path.module}/access_key.json"
    }
  }
}

# Read the access key credentials written by the script
data "local_file" "access_key" {
  depends_on = [terraform_data.access_key]
  filename   = "${path.module}/access_key.json"
}

locals {
  access_key = jsondecode(data.local_file.access_key.content)
}
