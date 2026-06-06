from pathlib import Path

from security_intelligence.cli import main
from tests.test_dashboard_support import build_full_dashboard_chain


def test_cli_export_dashboard_data_runs_after_full_local_chain(tmp_path: Path, capsys) -> None:
    outputs, _ = build_full_dashboard_chain(tmp_path)
    dashboard_dir = tmp_path / "dashboards"
    exports_dir = dashboard_dir / "exports"

    exit_code = main(
        [
            "export-dashboard-data",
            "--outputs-dir",
            str(outputs),
            "--dashboard-dir",
            str(dashboard_dir),
            "--exports-dir",
            str(exports_dir),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Dashboard exports generated" in captured.out
    assert (exports_dir / "executive_summary_metrics.csv").exists()
    assert (dashboard_dir / "dashboard_summary.json").exists()

