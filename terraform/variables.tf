variable "environment" {
  type        = string
  description = "Environment to deploy. Selects variable/<environment>.json (dev = develop branch, prd = main branch)."

  validation {
    condition     = contains(["dev", "prd"], var.environment)
    error_message = "environment must be either 'dev' or 'prd'."
  }
}

variable "variable_dir" {
  type        = string
  description = "Path (relative to the terraform/ dir) to the folder holding the per-environment JSON files."
  default     = "../variable"
}

variable "deploy_package" {
  type        = bool
  description = "When true, zip the packaged app and deploy it to the Function App via run-from-package."
  default     = true
}

variable "package_source_dir" {
  type        = string
  description = "Path (relative to the terraform/ dir) to the directory that gets zipped and deployed. For compiled runtimes point this at the build/publish output."
  default     = "../src"
}

variable "region_short_names" {
  type        = map(string)
  description = "Map of Azure region long name -> short token used in resource names."
  default = {
    eastus        = "eus"
    eastus2       = "eus2"
    centralus     = "cus"
    westus        = "wus"
    westus2       = "wus2"
    westus3       = "wus3"
    northeurope   = "neu"
    westeurope    = "weu"
    uksouth       = "uks"
    ukwest        = "ukw"
    southeastasia = "sea"
    centralindia  = "inc"
    southindia    = "ins"
  }
}

variable "log_analytics_retention_days" {
  type        = number
  description = "Retention in days for the Log Analytics workspace."
  default     = 30
}
