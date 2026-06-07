# Local Demo

This guide runs the full platform locally using synthetic data only. It does not require Azure CLI,
cloud credentials, Terraform, Bicep CLI, Power BI APIs, Microsoft Graph, Defender XDR, Sentinel, or
external AI services.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

## Quality Checks

```bash
python -m pytest
python -m ruff check .
```

## Health Check

```bash
python -m security_intelligence.cli health-check
python -m security_intelligence.cli show-config
```

## Full Local Pipeline

```bash
python -m security_intelligence.cli generate-telemetry --days 30 --users 50 --seed 42
python -m security_intelligence.cli ingest-telemetry --input-dir data/raw --output-dir data/processed
python -m security_intelligence.cli validate-telemetry --input-dir data/processed
python -m security_intelligence.cli run-detections --input-dir data/processed
python -m security_intelligence.cli run-identity-checks --input-dir data/processed
python -m security_intelligence.cli score-risk
python -m security_intelligence.cli monitor-platform
python -m security_intelligence.cli generate-copilot-briefs
python -m security_intelligence.cli export-dashboard-data
```

You can also run the same sequence with:

```bash
bash scripts/run_all_local.sh
```

## Expected Output Artifacts

Raw telemetry:

- `data/raw/identity_events.jsonl`
- `data/raw/login_events.jsonl`
- `data/raw/endpoint_events.jsonl`
- `data/raw/application_events.jsonl`
- `data/raw/security_alerts.jsonl`
- `data/raw/cloud_activity.jsonl`

Processed telemetry:

- `data/processed/identity_events.csv`
- `data/processed/login_events.csv`
- `data/processed/endpoint_events.csv`
- `data/processed/application_events.csv`
- `data/processed/security_alerts.csv`
- `data/processed/cloud_activity.csv`

Machine-readable outputs:

- `outputs/ingestion_summary.json`
- `outputs/data_quality_summary.json`
- `outputs/security_findings.json`
- `outputs/identity_governance_findings.json`
- `outputs/identity_review.csv`
- `outputs/risk_scores.json`
- `outputs/risk_scores.csv`
- `outputs/operational_health_summary.json`
- `outputs/evidence_manifest.json`
- `outputs/copilot_context.json`

Reports:

- `reports/data_quality_report.md`
- `reports/security_findings_report.md`
- `reports/identity_governance_report.md`
- `reports/risk_scoring_report.md`
- `reports/operational_evidence_report.md`
- `reports/copilot_investigation_summary.md`
- `reports/copilot_soc_triage_note.md`
- `reports/copilot_executive_brief.md`
- `reports/copilot_remediation_plan.md`
- `reports/copilot_compliance_evidence_summary.md`

Dashboard exports:

- `dashboards/exports/security_findings_dashboard.csv`
- `dashboards/exports/identity_governance_dashboard.csv`
- `dashboards/exports/risk_scores_dashboard.csv`
- `dashboards/exports/operational_health_dashboard.csv`
- `dashboards/exports/executive_summary_metrics.csv`
- `dashboards/exports/evidence_manifest_dashboard.csv`
- `dashboards/dashboard_summary.json`
