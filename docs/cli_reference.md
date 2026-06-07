# CLI Reference

Run commands with either `python -m security_intelligence.cli` or the installed
`security-intelligence` console script after installing the package.

## `health-check`

Purpose: Confirm the local platform scaffold is ready.

Example:

```bash
python -m security_intelligence.cli health-check
```

Inputs: none.

Outputs: console health message.

## `show-config`

Purpose: Load and print `configs/platform.yaml`.

Example:

```bash
python -m security_intelligence.cli show-config
```

Inputs: `configs/platform.yaml`.

Outputs: parsed configuration printed to the console.

## `generate-telemetry`

Purpose: Generate deterministic synthetic JSONL telemetry.

Example:

```bash
python -m security_intelligence.cli generate-telemetry --days 30 --users 50 --seed 42
```

Inputs: generation options.

Outputs: `data/raw/*.jsonl`.

## `ingest-telemetry`

Purpose: Convert raw JSONL datasets into processed CSV datasets.

Example:

```bash
python -m security_intelligence.cli ingest-telemetry --input-dir data/raw --output-dir data/processed
```

Inputs: `data/raw/*.jsonl`.

Outputs: `data/processed/*.csv`, `outputs/ingestion_summary.json`.

## `validate-telemetry`

Purpose: Validate processed CSV files and generate data quality evidence.

Example:

```bash
python -m security_intelligence.cli validate-telemetry --input-dir data/processed
```

Inputs: `data/processed/*.csv`.

Outputs: `outputs/data_quality_summary.json`, `reports/data_quality_report.md`.

## `run-detections`

Purpose: Run deterministic threat detection rules with MITRE ATT&CK mapping.

Example:

```bash
python -m security_intelligence.cli run-detections --input-dir data/processed
```

Inputs: processed telemetry CSV files and `configs/detection_rules.yaml`.

Outputs: `outputs/security_findings.json`, `reports/security_findings_report.md`.

## `run-identity-checks`

Purpose: Run deterministic identity governance checks.

Example:

```bash
python -m security_intelligence.cli run-identity-checks --input-dir data/processed
```

Inputs: processed identity, login, application, cloud, and alert CSV files.

Outputs: `outputs/identity_governance_findings.json`, `outputs/identity_review.csv`,
`reports/identity_governance_report.md`.

## `score-risk`

Purpose: Generate explainable risk scores from security, governance, and quality evidence.

Example:

```bash
python -m security_intelligence.cli score-risk
```

Inputs: `outputs/security_findings.json`, `outputs/identity_governance_findings.json`,
`outputs/data_quality_summary.json`, and optional processed telemetry.

Outputs: `outputs/risk_scores.json`, `outputs/risk_scores.csv`, `reports/risk_scoring_report.md`.

## `monitor-platform`

Purpose: Generate operational health and evidence outputs.

Example:

```bash
python -m security_intelligence.cli monitor-platform
```

Inputs: ingestion, validation, detection, identity, and risk outputs.

Outputs: `outputs/operational_health_summary.json`, `outputs/evidence_manifest.json`,
`reports/operational_evidence_report.md`.

## `generate-copilot-briefs`

Purpose: Generate local simulated GenAI-style investigation reports.

Example:

```bash
python -m security_intelligence.cli generate-copilot-briefs
```

Inputs: security findings, identity findings, risk scores, operational health, and evidence manifest.

Outputs: `outputs/copilot_context.json` and five `reports/copilot_*.md` reports.

## `export-dashboard-data`

Purpose: Export dashboard-ready CSV datasets and dashboard summary metadata.

Example:

```bash
python -m security_intelligence.cli export-dashboard-data
```

Inputs: platform output JSON files and optional CSV files.

Outputs: `dashboards/exports/*.csv`, `dashboards/dashboard_summary.json`,
`dashboards/README.md`, and `dashboards/streamlit_app.py`.

