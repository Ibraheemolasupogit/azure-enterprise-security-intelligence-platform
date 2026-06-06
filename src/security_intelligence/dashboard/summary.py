"""Dashboard summary and documentation writers."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

RECOMMENDED_DASHBOARD_PAGES = [
    "Executive Security Overview",
    "SOC Findings Overview",
    "Identity Governance Review",
    "Risk Prioritisation",
    "Operational Evidence",
    "Copilot Investigation Briefs",
]


def write_dashboard_summary(
    dashboard_dir: str | Path,
    exports_created: list[str],
    executive_metrics: list[dict[str, Any]],
    source_artifacts: list[str],
) -> dict[str, Any]:
    """Write dashboard summary JSON."""
    dashboard_path = Path(dashboard_dir)
    dashboard_path.mkdir(parents=True, exist_ok=True)
    summary = {
        "generated_timestamp": datetime.now(UTC).isoformat(),
        "dashboard_exports_created": exports_created,
        "executive_metrics": executive_metrics,
        "recommended_dashboard_pages": RECOMMENDED_DASHBOARD_PAGES,
        "source_artifacts_used": source_artifacts,
    }
    (dashboard_path / "dashboard_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary


def write_dashboard_readme(dashboard_dir: str | Path) -> None:
    """Create or update dashboard README documentation."""
    path = Path(dashboard_dir) / "README.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        """# Dashboard Exports

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
""",
        encoding="utf-8",
    )


def write_streamlit_placeholder(dashboard_dir: str | Path) -> None:
    """Create a lightweight optional Streamlit placeholder app."""
    path = Path(dashboard_dir) / "streamlit_app.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        '''"""Optional local Streamlit placeholder for dashboard exports."""

from pathlib import Path

import pandas as pd

try:
    import streamlit as st
except ModuleNotFoundError:  # pragma: no cover - Streamlit is optional.
    st = None


EXPORTS_DIR = Path(__file__).parent / "exports"


def load_csv(name: str) -> pd.DataFrame:
    path = EXPORTS_DIR / name
    if not path.exists():
        return pd.DataFrame()
    return pd.read_csv(path)


def main() -> None:
    if st is None:
        print("Streamlit is not installed. Install streamlit to run this optional dashboard.")
        return

    st.title("Azure Enterprise Security Intelligence Platform")
    st.caption("Local-first dashboard placeholder using exported CSV files.")

    metrics = load_csv("executive_summary_metrics.csv")
    risks = load_csv("risk_scores_dashboard.csv")
    security = load_csv("security_findings_dashboard.csv")
    identity = load_csv("identity_governance_dashboard.csv")
    health = load_csv("operational_health_dashboard.csv")

    st.header("Executive Metrics")
    st.dataframe(metrics)
    st.header("Top Risk Scores")
    st.dataframe(risks.head(20))
    st.header("Security Findings")
    st.dataframe(security.head(20))
    st.header("Identity Governance")
    st.dataframe(identity.head(20))
    st.header("Operational Health")
    st.dataframe(health)


if __name__ == "__main__":
    main()
''',
        encoding="utf-8",
    )
