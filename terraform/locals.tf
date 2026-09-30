locals {
  # Region short token used inside names. Falls back to the raw location if not mapped.
  region_short = lookup(var.region_short_names, local.location, local.location)

  # Global naming standard building blocks (CAF-style):
  #   <type>-<workload>-<env>-<region>-<instance>   (dashed)
  #   <type><workload><env><region><instance>       (compact, for storage)
  suffix         = "${local.workload}-${local.environment}-${local.region_short}-${local.instance}"
  suffix_compact = "${local.workload}${local.environment}${local.region_short}${local.instance}"

  # Resource names derived from the standard.
  resource_group_name   = "rg-${local.suffix}"
  app_service_plan_name = "asp-${local.suffix}"
  function_app_name     = "func-${local.suffix}"
  app_insights_name     = "appi-${local.suffix}"
  log_analytics_name    = "log-${local.suffix}"

  # Key Vault names are 3-24 chars, alphanumeric + dashes.
  key_vault_name = substr("kv-${local.suffix}", 0, 24)

  # Storage account: 3-24 chars, lowercase alphanumeric only, globally unique.
  storage_account_name = substr("st${local.suffix_compact}", 0, 24)

  # Storage sub-resources that need private endpoints for Durable Functions.
  storage_subresources = ["blob", "file", "queue", "table"]

  # Tags applied to every resource.
  common_tags = merge(
    {
      workload    = local.workload
      environment = local.environment
      managed_by  = "terraform"
      repo        = "cis-eng-functionapps"
    },
    local.extra_tags,
  )
}
