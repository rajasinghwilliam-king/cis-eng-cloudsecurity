########################################
# Key Vault (private, RBAC-authorized)
########################################

resource "azurerm_key_vault" "this" {
  name                          = local.key_vault_name
  resource_group_name           = azurerm_resource_group.this.name
  location                      = azurerm_resource_group.this.location
  tenant_id                     = local.tenant_id
  sku_name                      = local.key_vault_sku
  rbac_authorization_enabled    = true
  purge_protection_enabled      = local.key_vault_purge_protection
  soft_delete_retention_days    = local.key_vault_soft_delete_retention
  public_network_access_enabled = false
  tags                          = local.common_tags

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }
}

# The Function App's managed identity can read secrets and resolve Key Vault references
# (e.g. app settings of the form @Microsoft.KeyVault(SecretUri=...)).
resource "azurerm_role_assignment" "func_kv_secrets_user" {
  scope                = azurerm_key_vault.this.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = module.function_app.function_app_principal_id
}

# Private endpoint for the vault (subresource "vault").
module "key_vault_private_endpoint" {
  source = "./modules/private_endpoint"

  name                 = "pep-${local.key_vault_name}"
  location             = azurerm_resource_group.this.location
  resource_group_name  = azurerm_resource_group.this.name
  subnet_id            = data.azurerm_subnet.private_endpoint.id
  target_resource_id   = azurerm_key_vault.this.id
  subresource_names    = ["vault"]
  private_dns_zone_ids = try([local.private_dns_zone_ids["vault"]], [])
  tags                 = local.common_tags
}
