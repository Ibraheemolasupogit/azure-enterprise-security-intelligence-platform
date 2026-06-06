from pathlib import Path

from security_intelligence.cli import main
from security_intelligence.ingestion.pipeline import ingest_telemetry
from security_intelligence.telemetry.generator import generate_telemetry


def test_cli_validate_telemetry_runs_successfully_after_ingestion(
    tmp_path: Path, capsys
) -> None:
    raw_dir = tmp_path / "raw"
    processed_dir = tmp_path / "processed"
    summary_path = tmp_path / "outputs" / "data_quality_summary.json"
    report_path = tmp_path / "reports" / "data_quality_report.md"
    generate_telemetry(raw_dir, days=7, users=8, seed=123)
    ingest_telemetry(raw_dir, processed_dir, tmp_path / "outputs" / "ingestion_summary.json")

    exit_code = main(
        [
            "validate-telemetry",
            "--input-dir",
            str(processed_dir),
            "--summary-path",
            str(summary_path),
            "--report-path",
            str(report_path),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Telemetry validation complete" in captured.out
    assert "Overall data quality score" in captured.out
    assert summary_path.exists()
    assert report_path.exists()
