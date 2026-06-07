@description('Azure region for the reference architecture resources.')
param location string = resourceGroup().location

@description('Short environment name such as dev, test, or prod.')
param environmentName string = 'dev'

@description('Prefix used for reference resource names. Replace before any real deployment.')
param resourcePrefix string = 'aesi-reference'

@description('Log Analytics retention in days for reference planning.')
param logRetentionDays int = 30

var safePrefix = '${resourcePrefix}-${environmentName}'

resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: '${safePrefix}-law'
  location: location
  properties: {
    retentionInDays: logRetentionDays
    sku: {
      name: 'PerGB2018'
    }
  }
  tags: {
    workload: 'security-intelligence-reference'
    environment: environmentName
    deploymentMode: 'documentation-only'
  }
}

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: toLower(replace('${resourcePrefix}${environmentName}data', '-', ''))
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    accessTier: 'Hot'
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_2'
  }
  tags: {
    workload: 'security-intelligence-reference'
    environment: environmentName
    deploymentMode: 'documentation-only'
  }
}

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: '${safePrefix}-kv'
  location: location
  properties: {
    tenantId: subscription().tenantId
    enableRbacAuthorization: true
    sku: {
      family: 'A'
      name: 'standard'
    }
  }
  tags: {
    workload: 'security-intelligence-reference'
    environment: environmentName
    deploymentMode: 'documentation-only'
  }
}

output logAnalyticsWorkspaceName string = logAnalytics.name
output storageAccountName string = storage.name
output keyVaultName string = keyVault.name

