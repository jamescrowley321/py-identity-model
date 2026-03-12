terraform {
  required_version = ">= 1.5"

  required_providers {
    descope = {
      source  = "descope/descope"
      version = "~> 0.3"
    }
    github = {
      source  = "integrations/github"
      version = "~> 6.0"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.5"
    }
  }
}

provider "descope" {}

provider "github" {
  owner = "jamescrowley321"
}
