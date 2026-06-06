# Architecture

## Local-First Design

The Azure Enterprise Security Intelligence Platform begins as a local-first security analytics scaffold. Milestone 1 establishes the repository structure, configuration boundaries, documentation foundation, and test entry points without connecting to Azure or using paid services.

Future milestones will add functional layers incrementally while keeping local execution and synthetic data at the center of development.

## Synthetic Telemetry Layer

The synthetic telemetry layer will generate representative enterprise security events such as sign-in logs, audit records, endpoint alerts, network activity, identity inventory, and privileged access records. This layer will allow realistic analytics workflows without using real customer data or production cloud services.

## Ingestion Layer

The ingestion layer will load raw telemetry into local project directories, normalize basic schemas, and prepare records for validation and analysis. Its structure will map to future Azure Data Lake Storage and Azure Data Explorer patterns while remaining file-based during local development.

## Validation Layer

The validation layer will check data quality, required fields, expected values, timestamps, and schema consistency. It will help ensure detection rules, identity checks, risk scoring, and evidence generation operate on trustworthy inputs.

## Detection And Risk Layer

The detection and risk layer will evaluate local rules for suspicious activity, identity governance concerns, and security posture signals. Future milestones will add scoring and analytics patterns that prepare the project for machine learning without implementing models in the scaffold milestone.

## Reporting Layer

The reporting layer will produce investigation reports, compliance evidence, monitoring outputs, and dashboard-ready exports. These outputs will support both analyst workflows and executive communication.

## Future Azure Deployment Mapping

The local architecture is designed to map cleanly to Azure security services:

- Microsoft Sentinel for SIEM-style detection and investigation workflows
- Microsoft Entra ID for identity governance and privileged access signals
- Microsoft Defender XDR for endpoint and incident context
- Azure Data Explorer for high-scale telemetry analytics
- Azure Data Lake Storage for raw and curated security data zones
- Azure Machine Learning for future anomaly detection and risk scoring
- Azure AI Foundry for future GenAI-assisted security investigation workflows
- Azure Monitor for operational metrics and monitoring evidence
- Power BI for dashboard-ready reporting
- Azure Key Vault for future secret and configuration management

