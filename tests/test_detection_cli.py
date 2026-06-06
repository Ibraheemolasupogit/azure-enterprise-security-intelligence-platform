from pathlib import Path

from security_intelligence.cli import main
from security_intelligence.ingestion.pipeline import ingest_telemetry
from security_intelligence.telemetry.generator import generate_telemetry


def test_cli_run_detections_runs_successfully_after_ingestion(tmp_path: Path, capsys) -> None:
    raw_dir = tmp_path / "raw"
    processed_dir = tmp_path / "processed"
    output_path = tmp_path / "outputs" / "security_findings.json"
    report_path = tmp_path / "reports" / "security_findings_report.md"
    generate_telemetry(raw_dir, days=30, users=50, seed=42)
    ingest_telemetry(raw_dir, processed_dir, tmp_path / "outputs" / "ingestion_summary.json")

    exit_code = main(
        [
            "run-detections",
            "--input-dir",
            str(processed_dir),
            "--output-path",
            str(output_path),
            "--report-path",
            str(report_path),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Threat detections complete" in captured.out
    assert "Total findings" in captured.out
    assert output_path.exists()
    assert report_path.exists()

