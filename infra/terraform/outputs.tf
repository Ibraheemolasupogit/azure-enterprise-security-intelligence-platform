output "resource_group_name" {
  description = "Reference resource group name."
  value       = azurerm_resource_group.security_intelligence.name
}

output "log_analytics_workspace_name" {
  description = "Reference Log Analytics workspace name."
  value       = azurerm_log_analytics_workspace.security.name
}

output "storage_account_name" {
  description = "Reference storage account name."
  value       = azurerm_storage_account.security_data.name
}

output "key_vault_name" {
  description = "Reference Key Vault name."
  value       = azurerm_key_vault.security.name
}

