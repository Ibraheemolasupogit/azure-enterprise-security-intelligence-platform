terraform {
  required_version = ">= 1.6.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.100"
    }
  }
}

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "security_intelligence" {
  name     = "${var.resource_prefix}-${var.environment_name}-rg"
  location = var.location

  tags = local.common_tags
}

resource "azurerm_log_analytics_workspace" "security" {
  name                = "${var.resource_prefix}-${var.environment_name}-law"
  location            = azurerm_resource_group.security_intelligence.location
  resource_group_name = azurerm_resource_group.security_intelligence.name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days

  tags = local.common_tags
}

resource "azurerm_storage_account" "security_data" {
  name                     = lower(replace("${var.resource_prefix}${var.environment_name}data", "-", ""))
  resource_group_name      = azurerm_resource_group.security_intelligence.name
  location                 = azurerm_resource_group.security_intelligence.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"

  tags = local.common_tags
}

resource "azurerm_key_vault" "security" {
  name                       = "${var.resource_prefix}-${var.environment_name}-kv"
  location                   = azurerm_resource_group.security_intelligence.location
  resource_group_name        = azurerm_resource_group.security_intelligence.name
  tenant_id                  = var.placeholder_tenant_id
  sku_name                   = "standard"
  enable_rbac_authorization  = true
  purge_protection_enabled   = false
  soft_delete_retention_days = 7

  tags = local.common_tags
}

locals {
  common_tags = {
    workload       = "security-intelligence-reference"
    environment    = var.environment_name
    deploymentMode = "documentation-only"
  }
}

