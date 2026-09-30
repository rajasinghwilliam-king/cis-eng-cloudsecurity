provider "azurerm" {
  features {}

  # Sourced from variable/<environment>.json. Authentication is via GitHub OIDC in CI
  # (ARM_USE_OIDC=true, ARM_CLIENT_ID/ARM_TENANT_ID) and via `az login` for local runs.
  subscription_id = local.subscription_id
  tenant_id       = local.tenant_id
}
