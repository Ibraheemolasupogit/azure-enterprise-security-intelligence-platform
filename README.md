# Azure Enterprise Security Intelligence Platform

A production-style Azure security analytics and AI platform that simulates enterprise telemetry ingestion, identity governance, threat detection, security posture monitoring, anomaly detection, compliance evidence generation, and future GenAI-assisted security investigations using a local-first implementation mapped to Microsoft security services.

## Business Problem

Enterprise security teams often work across disconnected tools, fragmented telemetry sources, and overlapping alert queues. SOC analysts face alert overload while identity teams struggle to maintain strong governance over privileged access, dormant accounts, and risky sign-in patterns. Investigations can be slow because evidence, context, detections, and risk indicators are spread across separate systems.

At the same time, security leaders need reliable compliance evidence, executive-ready reporting, and measurable security posture insights. Many organizations also want AI-assisted investigation workflows, but they need a responsible foundation first: clean telemetry, trustworthy detections, governed identity signals, traceable evidence, and architecture that maps clearly to enterprise cloud security services.

This project creates that foundation locally before introducing cloud deployment, machine learning, or GenAI capabilities.

## Target Users

- SOC analysts
- Security engineers
- Cloud security engineers
- Identity engineers
- Security data scientists
- AI engineers
- Security architects
- Risk teams
- Compliance teams
- Executives

## MVP Capabilities

- Synthetic security telemetry
- Telemetry ingestion
- Validation
- Detection rules
- Identity governance checks
- Risk scoring
- Investigation reports
- Compliance evidence
- Monitoring outputs
- Dashboard-ready exports

## Azure Capability Mapping

| Local component | Azure service mapping | Purpose |
| --- | --- | --- |
| Synthetic telemetry samples | Microsoft Sentinel, Microsoft Defender XDR, Microsoft Entra ID | Simulate enterprise security events before connecting to real sources. |
| Telemetry ingestion pipeline | Azure Data Explorer, Azure Data Lake Storage, Azure Monitor | Prepare data engineering patterns for log ingestion and operational monitoring. |
| Detection rules | Microsoft Sentinel | Model detection engineering workflows with local YAML rule metadata. |
| Identity governance checks | Microsoft Entra ID | Represent Zero Trust identity posture checks and access review logic. |
| Risk scoring and analytics | Azure Machine Learning | Keep the platform ready for future anomaly detection and scoring models. |
| Investigation reports | Microsoft Defender XDR, Microsoft Sentinel | Generate analyst-friendly evidence and investigation summaries. |
| Compliance evidence | Microsoft Purview-aligned evidence workflows, Azure Monitor | Produce auditable control evidence from security telemetry and checks. |
| GenAI investigation workflows | Azure AI Foundry | Reserve a future path for responsible security copilot capabilities. |
| Dashboard-ready exports | Power BI | Prepare curated outputs for executive and operational dashboards. |
| Local secrets placeholders | Azure Key Vault | Establish configuration boundaries without storing real credentials. |

## Portfolio Positioning

This repository is designed as a professional cybersecurity analytics and cloud security engineering portfolio project. It demonstrates Zero Trust thinking, security data engineering, detection engineering, identity governance, ML-readiness, GenAI-readiness, compliance evidence design, and executive reporting practices.

The implementation is intentionally local-first. It avoids paid services, real credentials, and live Azure connections while still mapping the architecture to Microsoft security services used in enterprise environments.

## Current Milestone Status

| Milestone | Name | Status |
| --- | --- | --- |
| 1 | Scaffold | Complete |
| 2 | Synthetic telemetry | Complete |
| 3 | Ingestion pipeline | Complete |
| 4 | Validation and data quality | Planned |
| 5 | Threat detection rules | Planned |
| 6 | Identity governance checks | Planned |
| 7 | Risk scoring and analytics | Planned |
| 8 | Monitoring and operational evidence | Planned |
| 9 | GenAI security investigation copilot | Planned |
| 10 | Dashboard and reporting exports | Planned |
| 11 | Azure architecture and deployment design | Planned |
| 12 | Portfolio polish | Planned |

## Synthetic Telemetry Datasets

Milestone 2 adds deterministic synthetic telemetry generation for six local JSONL datasets:

- `data/raw/identity_events.jsonl`
- `data/raw/login_events.jsonl`
- `data/raw/endpoint_events.jsonl`
- `data/raw/application_events.jsonl`
- `data/raw/security_alerts.jsonl`
- `data/raw/cloud_activity.jsonl`

The generated records are artificial and safe for public repositories. They do not contain real users, real credentials, real tenant identifiers, or live Azure data. The datasets include normal activity and a small number of linked suspicious scenarios, such as impossible travel leading to an alert, privileged role assignment followed by cloud control-plane activity, malware detection leading to an alert, and dormant privileged account evidence.

Generate the default local telemetry:

```bash
python -m security_intelligence.cli generate-telemetry --days 30 --users 50 --seed 42
```

## Telemetry Ingestion

Milestone 3 adds a local ingestion pipeline that reads the raw synthetic JSONL files from `data/raw/`, verifies that all expected datasets are present, parses records safely, and writes processed CSV files to `data/processed/`. The pipeline also creates `outputs/ingestion_summary.json` with dataset-level record counts, column counts, source paths, processed paths, status, and total records ingested.

Run the raw-to-processed flow:

```bash
python -m security_intelligence.cli generate-telemetry --days 30 --users 50 --seed 42
python -m security_intelligence.cli ingest-telemetry --input-dir data/raw --output-dir data/processed
```

The processed CSV files are designed for downstream validation, detection engineering, identity governance checks, risk scoring, dashboards, and investigation reports in later milestones.

## Local Development

Install the package in editable mode with development dependencies:

```bash
python -m pip install -e ".[dev]"
```

Run the scaffold health check:

```bash
security-intelligence health-check
```

Show the local platform configuration:

```bash
security-intelligence show-config
```

Generate synthetic telemetry:

```bash
security-intelligence generate-telemetry --days 30 --users 50 --seed 42
```

Ingest synthetic telemetry:

```bash
security-intelligence ingest-telemetry --input-dir data/raw --output-dir data/processed
```

Run tests:

```bash
pytest
```
