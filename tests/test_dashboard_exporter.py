from pathlib import Path

import pandas as pd

from security_intelligence.dashboard.exporter import export_dashboard_data
from tests.test_dashboard_support import build_full_dashboard_chain

REQUIRED_EXPORTS = {
    "security_findings_dashboard.csv",
    "identity_governance_dashboard.csv",
    "risk_scores_dashboard.csv",
    "operational_health_dashboard.csv",
    "executive_summary_metrics.csv",
    "evidence_manifest_dashboard.csv",
}


def test_dashboard_exporter_creates_required_csv_exports_and_summary(tmp_path: Path) -> None:
    outputs, _ = build_full_dashboard_chain(tmp_path)
    dashboard_dir = tmp_path / "dashboards"
    exports_dir = dashboard_dir / "exports"

    result = export_dashboard_data(outputs, dashboard_dir, exports_dir)

    created_names = {Path(path).name for path in result["exports_created"]}
    assert REQUIRED_EXPORTS.issubset(created_names)
    assert (dashboard_dir / "dashboard_summary.json").exists()
    assert (dashboard_dir / "README.md").exists()
    assert (dashboard_dir / "streamlit_app.py").exists()


def test_exports_are_valid_csv_files(tmp_path: Path) -> None:
    outputs, _ = build_full_dashboard_chain(tmp_path)
    dashboard_dir = tmp_path / "dashboards"
    exports_dir = dashboard_dir / "exports"
    export_dashboard_data(outputs, dashboard_dir, exports_dir)

    for filename in REQUIRED_EXPORTS:
        dataframe = pd.read_csv(exports_dir / filename)
        assert list(dataframe.columns)


def test_missing_optional_inputs_are_handled_with_empty_exports(tmp_path: Path) -> None:
    outputs = tmp_path / "outputs"
    outputs.mkdir()
    dashboard_dir = tmp_path / "dashboards"
    exports_dir = dashboard_dir / "exports"

    result = export_dashboard_data(outputs, dashboard_dir, exports_dir)

    assert len(result["exports_created"]) == 6
    metrics = pd.read_csv(exports_dir / "executive_summary_metrics.csv")
    assert "copilot_context_generated" in set(metrics["metric_name"])

