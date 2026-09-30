terraform {
  # Partial backend configuration. The concrete values are supplied per environment
  # at init time, e.g.:
  #   terraform init -backend-config=environments/dev.backend.hcl
  #   terraform init -backend-config=environments/prd.backend.hcl
  backend "azurerm" {}
}
