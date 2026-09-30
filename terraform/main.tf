########################################
# Resource group
########################################

resource "azurerm_resource_group" "this" {
  name     = local.resource_group_name
  location = local.location
  tags     = local.common_tags
}

########################################
# Observability: Log Analytics + Application Insights
########################################

resource "azurerm_log_analytics_workspace" "this" {
  name                = local.log_analytics_name
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  sku                 = "PerGB2018"
  retention_in_days   = var.log_analytics_retention_days
  tags                = local.common_tags
}

resource "azurerm_application_insights" "this" {
  name                = local.app_insights_name
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  workspace_id        = azurerm_log_analytics_workspace.this.id
  application_type    = "web"
  tags                = local.common_tags
}

########################################
# App Service Plan + Storage + Function App (VNet integrated)
########################################

module "function_app" {
  source = "./modules/function_app"

  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location

  app_service_plan_name  = local.app_service_plan_name
  app_service_plan_sku   = local.app_service_plan_sku
  os_type                = local.os_type
  zone_balancing_enabled = local.zone_balancing_enabled

  function_app_name        = local.function_app_name
  functions_worker_runtime = local.functions_worker_runtime
  dotnet_version           = local.dotnet_version
  always_on                = local.always_on
  additional_app_settings  = merge(local.app_settings, {
    KEY_VAULT_URI = azurerm_key_vault.this.vault_uri
  })

  storage_account_name     = local.storage_account_name
  storage_replication_type = local.storage_replication_type

  integration_subnet_id                  = data.azurerm_subnet.integration.id
  application_insights_connection_string = azurerm_application_insights.this.connection_string

  # Code deployment (zip -> run-from-package)
  deploy_package  = var.deploy_package
  package_path    = var.deploy_package ? data.archive_file.package[0].output_path : null
  package_hash    = var.deploy_package ? data.archive_file.package[0].output_md5 : null
  deploy_agent_ip = var.deploy_agent_ip

  tags = local.common_tags
}

########################################
# Private endpoint: Function App (sites)
########################################

module "function_app_private_endpoint" {
  source = "./modules/private_endpoint"

  name                 = "pep-${local.function_app_name}"
  location             = azurerm_resource_group.this.location
  resource_group_name  = azurerm_resource_group.this.name
  subnet_id            = data.azurerm_subnet.private_endpoint.id
  target_resource_id   = module.function_app.function_app_id
  subresource_names    = ["sites"]
  private_dns_zone_ids = try([local.private_dns_zone_ids["sites"]], [])
  tags                 = local.common_tags
}

########################################
# Private endpoints: Storage (blob/file/queue/table) for Durable Functions
########################################

module "storage_private_endpoints" {
  source   = "./modules/private_endpoint"
  for_each = toset(local.storage_subresources)

  name                 = "pep-${local.storage_account_name}-${each.key}"
  location             = azurerm_resource_group.this.location
  resource_group_name  = azurerm_resource_group.this.name
  subnet_id            = data.azurerm_subnet.private_endpoint.id
  target_resource_id   = module.function_app.storage_account_id
  subresource_names    = [each.key]
  private_dns_zone_ids = try([local.private_dns_zone_ids[each.key]], [])
  tags                 = local.common_tags
}
