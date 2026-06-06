"""Dashboard export engine."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd

from security_intelligence.dashboard.datasets import (
    evidence_manifest_dataframe,
    identity_governance_dataframe,
    load_dashboard_payloads,
    operational_health_dataframe,
    risk_scores_dataframe,
    security_findings_dataframe,
)
from security_intelligence.dashboard.metrics import build_executive_metrics
from security_intelligence.dashboard.summary import (
    write_dashboard_readme,
    write_dashboard_summary,
    write_streamlit_placeholder,
)
from security_intelligence.paths import OUTPUT_DIR

EXPORTS = {
    "security_findings_dashboard.csv": security_findings_dataframe,
    "identity_governance_dashboard.csv": identity_governance_dataframe,
    "risk_scores_dashboard.csv": risk_scores_dataframe,
    "operational_health_dashboard.csv": operational_health_dataframe,
    "evidence_manifest_dashboard.csv": evidence_manifest_dataframe,
}


def export_dashboard_data(
    outputs_dir: str | Path = OUTPUT_DIR,
    dashboard_dir: str | Path = "dashboards",
    exports_dir: str | Path = "dashboards/exports",
) -> dict[str, Any]:
    """Export dashboard-ready CSV datasets and documentation."""
    outputs_path = Path(outputs_dir)
    dashboard_path = Path(dashboard_dir)
    exports_path = Path(exports_dir)
    dashboard_path.mkdir(parents=True, exist_ok=True)
    exports_path.mkdir(parents=True, exist_ok=True)

    payloads = load_dashboard_payloads(outputs_path)
    executive_metrics = build_executive_metrics(payloads)
    exports_created = []

    for filename, builder in EXPORTS.items():
        path = exports_path / filename
        dataframe = builder(payloads)
        dataframe.to_csv(path, index=False)
        exports_created.append(str(path))

    metrics_path = exports_path / "executive_summary_metrics.csv"
    pd.DataFrame(executive_metrics).to_csv(metrics_path, index=False)
    exports_created.append(str(metrics_path))

    source_artifacts = [
        str(outputs_path / name)
        for name in [
            "ingestion_summary.json",
            "data_quality_summary.json",
            "security_findings.json",
            "identity_governance_findings.json",
            "risk_scores.json",
            "operational_health_summary.json",
            "evidence_manifest.json",
            "copilot_context.json",
        ]
    ]
    dashboard_summary = write_dashboard_summary(
        dashboard_path,
        exports_created,
        executive_metrics,
        source_artifacts,
    )
    write_dashboard_readme(dashboard_path)
    write_streamlit_placeholder(dashboard_path)

    return {
        "dashboard_summary": dashboard_summary,
        "exports_created": exports_created,
        "executive_metrics": executive_metrics,
        "dashboard_readme": str(dashboard_path / "README.md"),
        "streamlit_app": str(dashboard_path / "streamlit_app.py"),
    }

