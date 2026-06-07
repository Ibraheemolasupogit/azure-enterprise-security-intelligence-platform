variable "location" {
  description = "Azure region for reference architecture resources."
  type        = string
  default     = "eastus"
}

variable "environment_name" {
  description = "Short environment name such as dev, test, or prod."
  type        = string
  default     = "dev"
}

variable "resource_prefix" {
  description = "Reference resource prefix. Replace before any real deployment."
  type        = string
  default     = "aesi-reference"
}

variable "log_retention_days" {
  description = "Log Analytics retention days for planning."
  type        = number
  default     = 30
}

variable "placeholder_tenant_id" {
  description = "Placeholder tenant ID for documentation only. Do not use a real tenant ID in source."
  type        = string
  default     = "00000000-0000-0000-0000-000000000000"
}

