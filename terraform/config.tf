# Load the per-environment reference file (variable/<environment>.json) as the single
# reusable source of truth for subscription, network, service principal, state and app settings.
locals {
  config = jsondecode(file("${path.module}/${var.variable_dir}/${var.environment}.json"))

  # Normalized, defaulted views of the config used throughout the configuration.
  subscription_id          = local.config.subscription_id
  tenant_id                = local.config.tenant_id
  workload                 = local.config.workload
  environment              = local.config.environment
  location                 = local.config.location
  instance                 = try(local.config.instance, "001")
  app_service_plan_sku     = try(local.config.app_service_plan_sku, "EP1")
  os_type                  = try(local.config.os_type, "Windows")
  always_on                = try(local.config.always_on, false)
  zone_balancing_enabled   = try(local.config.zone_balancing_enabled, false)
  functions_worker_runtime = try(local.config.functions_worker_runtime, "dotnet-isolated")
  dotnet_version           = try(local.config.dotnet_version, "v8.0")
  storage_replication_type = try(local.config.storage_replication_type, "LRS")

  # Storage public access toggle (demo: dev on, prd private). Empty allowed_ip_rules with
  # public access on => open (default Allow); provide CIDRs => Deny + allowlist.
  storage_public_network_access = try(local.config.storage.public_network_access, false)
  storage_allowed_ip_rules      = try(local.config.storage.allowed_ip_rules, [])

  # Whether Terraform (running as the deploy SP) creates the RBAC role assignments that grant the
  # Function App's managed identity access to storage/Key Vault. Default false: a deploy-only
  # (Contributor) SP cannot assign roles, so an admin creates these separately. Set true only if
  # the deploy identity has Role Based Access Control Administrator / User Access Administrator.
  manage_role_assignments = try(local.config.manage_role_assignments, false)

  key_vault_sku                   = try(local.config.key_vault.sku, "standard")
  key_vault_purge_protection      = try(local.config.key_vault.purge_protection_enabled, false)
  key_vault_soft_delete_retention = try(local.config.key_vault.soft_delete_retention_days, 7)

  network           = local.config.network
  app_settings      = try(local.config.app_settings, {})
  extra_tags        = try(local.config.tags, {})

  # When false, Terraform does NOT create private endpoints or private DNS — you attach the
  # private links (and DNS) manually. The resources are still created with public access disabled.
  manage_private_endpoints = try(local.config.manage_private_endpoints, true)

  # Private DNS zone resolution, in priority order:
  #  1. create_private_dns_zones = true  -> Terraform creates + VNet-links the zones (greenfield tenant).
  #  2. private_dns_zone_resource_group set -> look up EXISTING central zones by name (no create/link).
  #  3. else -> use the explicit IDs in private_dns_zone_ids.
  create_private_dns_zones        = try(local.config.create_private_dns_zones, false)
  private_dns_zone_resource_group = try(local.config.private_dns_zone_resource_group, null)

  # Drop empty private DNS zone entries so unset zones are simply skipped.
  private_dns_zone_ids = {
    for k, v in try(local.config.private_dns_zone_ids, {}) : k => v if v != null && v != ""
  }
}
