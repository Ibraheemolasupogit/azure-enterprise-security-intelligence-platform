# Infrastructure Reference Design

This folder contains Azure architecture and deployment design artifacts for the Azure Enterprise
Security Intelligence Platform. It explains how the local-first repository could map to a
production Azure security intelligence environment.

The repository remains local-first. Nothing in this folder deploys cloud resources by default,
connects to Azure, stores credentials, or assumes access to a real tenant or subscription.

## Contents

- `azure_architecture.md`: target Azure architecture and service mapping
- `deployment_plan.md`: phased deployment approach and operational handover
- `security_controls.md`: security controls for identity, data, monitoring, and SDLC
- `cost_considerations.md`: cost drivers and optimisation considerations
- `environments.md`: local, dev, test, and prod environment strategy
- `bicep/`: safe Bicep reference skeletons
- `terraform/`: safe Terraform reference skeletons

## Local-First Versus Production Azure

The current platform generates synthetic telemetry, processes it locally, and writes JSON, CSV,
Markdown, and dashboard-ready outputs. A production Azure version would replace local files with
managed ingestion, storage, analytics, security operations, and reporting services.

The Bicep and Terraform examples are reference architecture templates for portfolio documentation.
They use placeholder names and safe defaults. They are intentionally incomplete for production use
and must be reviewed, secured, parameterised, and tested before any real deployment.

## Future Deployment Sequence

1. Confirm tenant, subscription, region, naming, tagging, and compliance requirements.
2. Provision foundation resources such as resource groups, Log Analytics, storage, Key Vault, and
   managed identities.
3. Enable security operations services such as Microsoft Sentinel, Defender integrations, and Azure
   Monitor diagnostics.
4. Add ingestion paths through Event Hub, diagnostic settings, and Microsoft security connectors.
5. Create analytics and reporting surfaces using Azure Data Explorer, Fabric or Power BI, and
   Sentinel workbooks.
6. Introduce future ML and GenAI workflows only after data governance, access controls, and evidence
   handling are mature.

