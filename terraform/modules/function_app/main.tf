########################################
# App Service Plan
########################################

resource "azurerm_service_plan" "this" {
  name                   = var.app_service_plan_name
  resource_group_name    = var.resource_group_name
  location               = var.location
  os_type                = var.os_type
  sku_name               = var.app_service_plan_sku
  zone_balancing_enabled = var.zone_balancing_enabled
  tags                   = var.tags
}

########################################
# Storage account (Function App backing store) - fully private
########################################

resource "azurerm_storage_account" "this" {
  name                            = var.storage_account_name
  resource_group_name             = var.resource_group_name
  location                        = var.location
  account_tier                    = "Standard"
  account_replication_type        = var.storage_replication_type
  account_kind                    = "StorageV2"
  min_tls_version                 = "TLS1_2"
  https_traffic_only_enabled      = true
  public_network_access_enabled   = false
  allow_nested_items_to_be_public = false
  shared_access_key_enabled       = true
  tags                            = var.tags

  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
  }
}

########################################
# Function App app settings (shared by Windows/Linux)
########################################

########################################
# Code deployment: zip -> blob -> run-from-package (managed identity)
########################################

resource "azurerm_storage_container" "deployments" {
  count                 = var.deploy_package ? 1 : 0
  name                  = "deployments"
  storage_account_name  = azurerm_storage_account.this.name
  container_access_type = "private"
}

resource "azurerm_storage_blob" "package" {
  count = var.deploy_package ? 1 : 0
  # Hash in the name makes the run-from-package URL change on new content, forcing a reload.
  name                   = "package-${var.package_hash}.zip"
  storage_account_name   = azurerm_storage_account.this.name
  storage_container_name = azurerm_storage_container.deployments[0].name
  type                   = "Block"
  source                 = var.package_path
}

# Let the Function App's managed identity read the package blob (SAS-less run-from-package).
resource "azurerm_role_assignment" "package_reader" {
  count                = var.deploy_package ? 1 : 0
  scope                = azurerm_storage_account.this.id
  role_definition_name = "Storage Blob Data Reader"
  principal_id         = local.function_app.identity[0].principal_id
}

locals {
  base_app_settings = {
    FUNCTIONS_WORKER_RUNTIME                 = var.functions_worker_runtime
    WEBSITE_CONTENTAZUREFILECONNECTIONSTRING = azurerm_storage_account.this.primary_connection_string
    WEBSITE_CONTENTSHARE                     = lower(var.function_app_name)
    # Route content share traffic through the VNet so it can reach the storage
    # file private endpoint (public access on storage is disabled).
    WEBSITE_CONTENTOVERVNET = "1"
    # Storage is locked behind private endpoints, so the platform cannot reach it
    # for content-share validation at deploy time. Skip that check; the platform
    # provisions the share over the VNet on first run.
    WEBSITE_SKIP_CONTENTSHARE_VALIDATION = "1"
  }

  # Run-from-package points at the uploaded blob. A URL with no SAS token makes the
  # platform authenticate with the app's system-assigned managed identity.
  run_from_package = var.deploy_package ? {
    WEBSITE_RUN_FROM_PACKAGE = "https://${azurerm_storage_account.this.name}.blob.core.windows.net/${azurerm_storage_container.deployments[0].name}/${azurerm_storage_blob.package[0].name}"
  } : {}

  app_settings = merge(local.base_app_settings, local.run_from_package, var.additional_app_settings)
}

########################################
# Windows Function App
########################################

resource "azurerm_windows_function_app" "this" {
  count = var.os_type == "Windows" ? 1 : 0

  name                          = var.function_app_name
  resource_group_name           = var.resource_group_name
  location                      = var.location
  service_plan_id               = azurerm_service_plan.this.id
  storage_account_name          = azurerm_storage_account.this.name
  storage_account_access_key    = azurerm_storage_account.this.primary_access_key
  functions_extension_version   = var.functions_extension_version
  virtual_network_subnet_id     = var.integration_subnet_id
  public_network_access_enabled = false
  https_only                    = true
  tags                          = var.tags

  identity {
    type = "SystemAssigned"
  }

  app_settings = local.app_settings

  site_config {
    always_on                              = var.always_on
    ftps_state                             = "Disabled"
    minimum_tls_version                    = "1.2"
    vnet_route_all_enabled                 = true
    application_insights_connection_string = var.application_insights_connection_string

    application_stack {
      dotnet_version              = var.dotnet_version
      use_dotnet_isolated_runtime = var.functions_worker_runtime == "dotnet-isolated"
    }
  }

  lifecycle {
    ignore_changes = [
      # The content share is created by the platform on first run.
      app_settings["WEBSITE_CONTENTSHARE"],
    ]
  }
}

########################################
# Linux Function App
########################################

resource "azurerm_linux_function_app" "this" {
  count = var.os_type == "Linux" ? 1 : 0

  name                          = var.function_app_name
  resource_group_name           = var.resource_group_name
  location                      = var.location
  service_plan_id               = azurerm_service_plan.this.id
  storage_account_name          = azurerm_storage_account.this.name
  storage_account_access_key    = azurerm_storage_account.this.primary_access_key
  functions_extension_version   = var.functions_extension_version
  virtual_network_subnet_id     = var.integration_subnet_id
  public_network_access_enabled = false
  https_only                    = true
  tags                          = var.tags

  identity {
    type = "SystemAssigned"
  }

  app_settings = local.app_settings

  site_config {
    always_on                              = var.always_on
    ftps_state                             = "Disabled"
    minimum_tls_version                    = "1.2"
    vnet_route_all_enabled                 = true
    application_insights_connection_string = var.application_insights_connection_string

    application_stack {
      dotnet_version              = var.dotnet_version
      use_dotnet_isolated_runtime = var.functions_worker_runtime == "dotnet-isolated"
    }
  }

  lifecycle {
    ignore_changes = [
      app_settings["WEBSITE_CONTENTSHARE"],
    ]
  }
}

locals {
  function_app = var.os_type == "Windows" ? azurerm_windows_function_app.this[0] : azurerm_linux_function_app.this[0]
}
