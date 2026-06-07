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
| 4 | Validation and data quality | Complete |
| 5 | Threat detection rules | Complete |
| 6 | Identity governance checks | Complete |
| 7 | Risk scoring and analytics | Complete |
| 8 | Monitoring and operational evidence | Complete |
| 9 | GenAI security investigation copilot | Complete |
| 10 | Dashboard and reporting exports | Complete |
| 11 | Azure architecture and deployment design | Complete |
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

## Validation And Data Quality

Milestone 4 adds a local validation layer for the processed telemetry CSV files in `data/processed/`. It checks file availability, empty files, required columns, missing IDs, duplicate IDs, timestamp parseability, severity values, risk hint values, and ingestion metadata columns.

Run validation after generating and ingesting telemetry:

```bash
python -m security_intelligence.cli validate-telemetry --input-dir data/processed
```

Validation writes two evidence outputs:

- `outputs/data_quality_summary.json`: machine-readable validation results, dataset scores, warnings, failures, and overall data quality score
- `reports/data_quality_report.md`: human-readable evidence report with an executive summary, dataset table, findings, score, and recommended next actions

The validation stage keeps the platform ready for downstream detection, identity governance, risk scoring, reporting, and auditability without connecting to Azure or using real data.

## Threat Detection Rules

Milestone 5 adds deterministic threat detection rules that run against the processed telemetry CSV files. The rules detect impossible travel, repeated failed logins, privileged role activation, suspicious PowerShell execution, malware detections, suspicious cloud control-plane changes, and bulk application exports.

Run detections after generating and ingesting telemetry:

```bash
python -m security_intelligence.cli run-detections --input-dir data/processed
```

Detection outputs include:

- `outputs/security_findings.json`: machine-readable findings, rule metadata, MITRE ATT&CK mapping, evidence, and severity summaries
- `reports/security_findings_report.md`: human-readable findings report with executive summary, top findings, MITRE coverage, and recommended next actions

Each finding includes MITRE ATT&CK tactic and technique fields where appropriate. The detection layer is deterministic, local-first, and based only on synthetic telemetry.

## Identity Governance Checks

Milestone 6 adds deterministic identity governance checks aligned to Microsoft Entra ID identity governance and Zero Trust access review concepts. The checks analyze synthetic identity, login, application, cloud activity, and alert telemetry to identify dormant users, dormant privileged accounts, MFA gaps, guest exposure, role sprawl, risky privilege assignments, and privileged cloud activity.

Run identity governance checks after generating and ingesting telemetry:

```bash
python -m security_intelligence.cli run-identity-checks --input-dir data/processed
```

Identity governance outputs include:

- `outputs/identity_governance_findings.json`: machine-readable governance findings with evidence and source datasets
- `outputs/identity_review.csv`: flattened user review table for access review workflows
- `reports/identity_governance_report.md`: human-readable governance report with category summaries, highest-risk users, and recommended actions

The identity governance layer is local-first, uses synthetic telemetry only, and does not call Microsoft Graph or Azure APIs.

## Risk Scoring And Analytics

Milestone 7 adds deterministic risk scoring that combines security findings, identity governance findings, data quality evidence, and local identity context into explainable entity risk records. This layer supports SOC prioritisation, Zero Trust governance reviews, executive reporting, downstream dashboards, and future ML-readiness without building ML models yet.

Run risk scoring after generating, ingesting, validating, running detections, and running identity checks:

```bash
python -m security_intelligence.cli score-risk
```

Risk scoring outputs include:

- `outputs/risk_scores.json`: machine-readable risk records, scoring weights, data quality context, top risks, and risk band counts
- `outputs/risk_scores.csv`: flattened risk score table for downstream analytics
- `reports/risk_scoring_report.md`: human-readable risk report with top entities, contributing factors, scoring method, and recommended actions

The scoring method is deterministic and explainable. It uses severity weights, identity governance category weights, privileged-role modifiers, multiple-category modifiers, and overlap between security and governance evidence.

## Monitoring And Operational Evidence

Milestone 8 adds local monitoring and operational evidence generation for pipeline health, dataset freshness, record counts, validation status, detection findings, identity governance findings, risk scoring outputs, and audit-ready evidence artifacts. It aligns conceptually to Azure Monitor, Microsoft Sentinel operational visibility, audit evidence, and security governance reporting while remaining fully local.

Run monitoring after the local pipeline has produced ingestion, validation, detection, identity governance, and risk outputs:

```bash
python -m security_intelligence.cli monitor-platform
```

Monitoring outputs include:

- `outputs/operational_health_summary.json`: machine-readable pipeline health summary, warnings, failures, key metrics, and recommended actions
- `outputs/evidence_manifest.json`: evidence pack manifest listing JSON, CSV, and Markdown artifacts with control alignment
- `reports/operational_evidence_report.md`: human-readable operational evidence report for SOC, audit, and executive visibility

The monitoring layer is deterministic, local-first, and based on synthetic local evidence only.

## Local-First GenAI Investigation Copilot Simulation

Milestone 9 adds a local-first GenAI security investigation copilot simulation. It uses deterministic prompt templates and rule-based Markdown generation to produce Security Copilot and Azure AI Foundry-style investigation outputs without calling Azure OpenAI, Azure AI Foundry, OpenAI, LangChain, Microsoft Graph, or any external service.

Run the simulated copilot after the local pipeline has produced monitoring and evidence outputs:

```bash
python -m security_intelligence.cli generate-copilot-briefs
```

Copilot simulation outputs include:

- `outputs/copilot_context.json`: structured investigation context from findings, risk scores, health, and evidence manifest artifacts
- `reports/copilot_investigation_summary.md`: security investigation summary
- `reports/copilot_soc_triage_note.md`: analyst-ready triage note
- `reports/copilot_executive_brief.md`: business-friendly executive incident brief
- `reports/copilot_remediation_plan.md`: remediation plan grouped by control area
- `reports/copilot_compliance_evidence_summary.md`: audit and evidence summary

Every generated report clearly states that it is a local simulated GenAI-style response based on synthetic platform outputs.

## Dashboard And Reporting Exports

Milestone 10 adds dashboard-ready CSV exports and lightweight local reporting artifacts for Power BI, Streamlit, executive reporting, SOC dashboards, governance dashboards, and operational review. The exports are generated locally from existing platform outputs and do not use Power BI APIs, Azure services, credentials, or hosted web infrastructure.

Run dashboard export generation after the local pipeline has produced copilot context and evidence outputs:

```bash
python -m security_intelligence.cli export-dashboard-data
```

Dashboard outputs include:

- `dashboards/exports/security_findings_dashboard.csv`
- `dashboards/exports/identity_governance_dashboard.csv`
- `dashboards/exports/risk_scores_dashboard.csv`
- `dashboards/exports/operational_health_dashboard.csv`
- `dashboards/exports/executive_summary_metrics.csv`
- `dashboards/exports/evidence_manifest_dashboard.csv`
- `dashboards/dashboard_summary.json`
- `dashboards/README.md`

The dashboard exports align to Power BI, SOC reporting, executive reporting, risk prioritisation, identity governance review, and operational evidence workflows.

## Azure Architecture And Deployment Design

Milestone 11 adds the production Azure architecture and deployment design layer. It documents how
the local-first platform maps to Azure security services and adds infrastructure skeletons,
environment strategy, security controls, cost considerations, and Mermaid diagrams for portfolio
review.

This milestone does not deploy Azure resources, connect to Azure, use Power BI APIs, store
credentials, or claim that the platform is running in a real tenant. The Bicep and Terraform files
are safe reference templates for architecture documentation only.

Architecture and deployment artifacts include:

- [`infra/README.md`](infra/README.md)
- [`infra/azure_architecture.md`](infra/azure_architecture.md)
- [`infra/deployment_plan.md`](infra/deployment_plan.md)
- [`infra/security_controls.md`](infra/security_controls.md)
- [`infra/cost_considerations.md`](infra/cost_considerations.md)
- [`infra/environments.md`](infra/environments.md)
- [`docs/production_architecture.md`](docs/production_architecture.md)
- [`docs/security_operations_model.md`](docs/security_operations_model.md)
- [`diagrams/azure_architecture.mmd`](diagrams/azure_architecture.mmd)
- [`diagrams/data_flow.mmd`](diagrams/data_flow.mmd)
- [`diagrams/security_operations_flow.mmd`](diagrams/security_operations_flow.mmd)

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

Validate processed telemetry:

```bash
security-intelligence validate-telemetry --input-dir data/processed
```

Run deterministic detections:

```bash
security-intelligence run-detections --input-dir data/processed
```

Run identity governance checks:

```bash
security-intelligence run-identity-checks --input-dir data/processed
```

Score risk:

```bash
security-intelligence score-risk
```

Monitor platform evidence:

```bash
security-intelligence monitor-platform
```

Generate local simulated copilot briefs:

```bash
security-intelligence generate-copilot-briefs
```

Export dashboard data:

```bash
security-intelligence export-dashboard-data
```

Run tests:

```bash
pytest
```
