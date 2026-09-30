output "function_app_id" {
  description = "Resource ID of the Function App."
  value       = local.function_app.id
}

output "function_app_name" {
  description = "Name of the Function App."
  value       = local.function_app.name
}

output "function_app_default_hostname" {
  description = "Default hostname of the Function App."
  value       = local.function_app.default_hostname
}

output "function_app_principal_id" {
  description = "System-assigned managed identity principal ID."
  value       = local.function_app.identity[0].principal_id
}

output "service_plan_id" {
  description = "Resource ID of the App Service Plan."
  value       = azurerm_service_plan.this.id
}

output "storage_account_id" {
  description = "Resource ID of the storage account."
  value       = azurerm_storage_account.this.id
}

output "storage_account_name" {
  description = "Name of the storage account."
  value       = azurerm_storage_account.this.name
}
