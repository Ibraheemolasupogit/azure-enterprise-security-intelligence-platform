# Architecture

## Local-First Design

The Azure Enterprise Security Intelligence Platform begins as a local-first security analytics scaffold. Milestone 1 establishes the repository structure, configuration boundaries, documentation foundation, and test entry points without connecting to Azure or using paid services.

Future milestones will add functional layers incrementally while keeping local execution and synthetic data at the center of development.

## Synthetic Telemetry Layer

The synthetic telemetry layer generates representative enterprise security records without using real users, credentials, tenant identifiers, or live Azure data. It writes local JSONL files under `data/raw/` for identity events, login events, endpoint events, application events, security alerts, and cloud control-plane activity.

Generation is deterministic through a configurable random seed. This keeps demos, tests, and future analytics work reproducible while still producing varied users, departments, devices, applications, locations, authentication methods, resources, and severity levels.

The layer includes both normal operational activity and a small set of linked suspicious scenarios:

- Impossible travel login activity that leads to a synthetic security alert
- Privileged role assignment followed by sensitive cloud activity
- Malware endpoint detection that leads to an alert
- Dormant privileged account evidence based on identity history

These datasets are intentionally raw outputs. Later milestones will add ingestion, validation, detection execution, identity governance checks, risk scoring, reporting, and dashboard exports.

## Ingestion Layer

The ingestion layer loads the raw synthetic JSONL files from `data/raw/`, verifies that every expected dataset from `configs/platform.yaml` is available, parses each JSONL record, and writes structured CSV outputs to `data/processed/`.

The raw-to-processed flow is intentionally simple:

1. Discover expected dataset filenames from platform configuration.
2. Fail fast with clear missing-file messages if required raw inputs are absent.
3. Read JSONL records while skipping blank lines and reporting invalid JSON with file and line number.
4. Convert each dataset into a pandas DataFrame.
5. Add ingestion metadata columns for timestamp, source dataset, and source file.
6. Write processed CSV files and `outputs/ingestion_summary.json`.

This keeps Milestone 3 focused on local ingestion only. Later milestones will use the processed CSV files for validation, detection rules, identity governance checks, risk scoring, monitoring evidence, and reporting.

## Validation Layer

The validation layer checks the processed CSV files in `data/processed/` before they are used by downstream analytics. It validates file availability, non-empty datasets, required columns, required identifier values, duplicate IDs, timestamp parseability, allowed severity values, allowed risk hint values, and ingestion metadata fields.

The local flow now moves through three evidence-producing stages:

1. Raw synthetic JSONL files in `data/raw/`
2. Processed CSV files in `data/processed/`
3. Validation evidence in `outputs/data_quality_summary.json` and `reports/data_quality_report.md`

Each dataset receives per-rule validation results, warning and failure lists, and a data quality score from 0 to 100. The platform also calculates an overall data quality score. This gives later milestones a traceable quality gate before detection rules, identity governance checks, risk scoring, monitoring evidence, and reporting.

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
