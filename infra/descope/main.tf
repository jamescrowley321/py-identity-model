terraform {
  required_version = ">= 1.5"

  required_providers {
    descope = {
      source  = "jamescrowley321/descope"
      version = "~> 1.0"
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
