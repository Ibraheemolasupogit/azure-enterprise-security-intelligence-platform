# Dashboard Exports

This directory contains local-first dashboard-ready exports for the Azure Enterprise Security
Intelligence Platform. The CSV files are designed for import into Power BI, Streamlit,
spreadsheets, or other reporting tools without using Power BI APIs or cloud services.

## Exported Datasets

- `exports/security_findings_dashboard.csv`
- `exports/identity_governance_dashboard.csv`
- `exports/risk_scores_dashboard.csv`
- `exports/operational_health_dashboard.csv`
- `exports/executive_summary_metrics.csv`
- `exports/evidence_manifest_dashboard.csv`

## Suggested Dashboard Pages

- Executive Security Overview
- SOC Findings Overview
- Identity Governance Review
- Risk Prioritisation
- Operational Evidence
- Copilot Investigation Briefs

## Suggested Visuals

- KPI cards
- Findings by severity
- Risk band distribution
- Top risky users/entities
- Identity governance categories
- Operational health table
- Evidence artifact coverage

## Local-First Note

These exports are generated locally from synthetic data and existing repository outputs. They do
not require Power BI APIs, Azure services, credentials, or paid cloud resources.
