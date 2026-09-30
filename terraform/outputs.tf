output "resource_group_name" {
  description = "Name of the created resource group."
  value       = azurerm_resource_group.this.name
}

output "app_service_plan_id" {
  description = "Resource ID of the App Service Plan."
  value       = module.function_app.service_plan_id
}

output "function_app_name" {
  description = "Name of the Function App."
  value       = module.function_app.function_app_name
}

output "function_app_id" {
  description = "Resource ID of the Function App."
  value       = module.function_app.function_app_id
}

output "function_app_default_hostname" {
  description = "Default hostname of the Function App (resolves to the private endpoint IP inside the VNet)."
  value       = module.function_app.function_app_default_hostname
}

output "function_app_principal_id" {
  description = "System-assigned managed identity principal ID of the Function App."
  value       = module.function_app.function_app_principal_id
}

output "storage_account_name" {
  description = "Name of the Function App storage account."
  value       = module.function_app.storage_account_name
}

output "key_vault_name" {
  description = "Name of the Key Vault."
  value       = azurerm_key_vault.this.name
}

output "key_vault_uri" {
  description = "URI of the Key Vault (resolves to the private endpoint inside the VNet)."
  value       = azurerm_key_vault.this.vault_uri
}

output "key_vault_private_endpoint_ip" {
  description = "Private IP of the Key Vault private endpoint."
  value       = module.key_vault_private_endpoint.private_ip_address
}

output "application_insights_connection_string" {
  description = "Application Insights connection string."
  value       = azurerm_application_insights.this.connection_string
  sensitive   = true
}

output "function_app_private_endpoint_ip" {
  description = "Private IP of the Function App private endpoint."
  value       = module.function_app_private_endpoint.private_ip_address
}

output "storage_private_endpoint_ips" {
  description = "Private IPs of the storage private endpoints keyed by sub-resource."
  value       = { for k, m in module.storage_private_endpoints : k => m.private_ip_address }
}
