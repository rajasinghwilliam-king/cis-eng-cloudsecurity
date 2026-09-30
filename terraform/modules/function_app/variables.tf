variable "resource_group_name" {
  type        = string
  description = "Resource group that hosts the plan, storage and function app."
}

variable "location" {
  type        = string
  description = "Azure region."
}

variable "app_service_plan_name" {
  type        = string
  description = "Name of the App Service Plan."
}

variable "app_service_plan_sku" {
  type        = string
  description = "SKU of the App Service Plan (EP1/EP2/EP3 or P1v3+)."
}

variable "os_type" {
  type        = string
  description = "Operating system: Windows or Linux."
}

variable "zone_balancing_enabled" {
  type        = bool
  description = "Enable zone balancing on the plan."
  default     = false
}

variable "function_app_name" {
  type        = string
  description = "Name of the Function App."
}

variable "storage_account_name" {
  type        = string
  description = "Name of the storage account backing the Function App."
}

variable "storage_replication_type" {
  type        = string
  description = "Storage replication (LRS, ZRS, GRS...)."
  default     = "LRS"
}

variable "storage_public_network_access" {
  type        = bool
  description = "Enable the storage account's public endpoint (private endpoints still apply). Keep false for fully private."
  default     = false
}

variable "storage_allowed_ip_rules" {
  type        = list(string)
  description = "IP/CIDR allowlist for the storage public endpoint. Empty + public access on => open (Allow); non-empty => Deny + allowlist. Ignored when public access is off."
  default     = []
}

variable "functions_worker_runtime" {
  type        = string
  description = "Functions worker runtime."
}

variable "functions_extension_version" {
  type        = string
  description = "Azure Functions runtime version."
  default     = "~4"
}

variable "dotnet_version" {
  type        = string
  description = ".NET version for dotnet stacks."
  default     = "v8.0"
}

variable "always_on" {
  type        = bool
  description = "Always On setting (false on Elastic Premium)."
  default     = false
}

variable "integration_subnet_id" {
  type        = string
  description = "Delegated subnet ID for regional VNet integration."
}

variable "application_insights_connection_string" {
  type        = string
  description = "Application Insights connection string."
  default     = null
}

variable "additional_app_settings" {
  type        = map(string)
  description = "Extra app settings merged into the Function App."
  default     = {}
}

variable "deploy_package" {
  type        = bool
  description = "When true, upload the zip package and configure run-from-package."
  default     = false
}

variable "manage_role_assignments" {
  type        = bool
  description = "When true, Terraform creates the role assignment granting the Function App MI Storage Blob Data Reader. Requires the deploy identity to have role-assignment rights."
  default     = false
}

variable "package_path" {
  type        = string
  description = "Local path to the zipped deployment package. Required when deploy_package is true."
  default     = null
}

variable "package_hash" {
  type        = string
  description = "Content hash of the package, used in the blob name to force a reload on change. Required when deploy_package is true."
  default     = null
}

variable "tags" {
  type        = map(string)
  description = "Tags applied to all resources in this module."
  default     = {}
}
