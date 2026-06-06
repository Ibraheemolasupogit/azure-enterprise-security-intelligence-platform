import json
from pathlib import Path

import pytest

from security_intelligence.ingestion.pipeline import ingest_telemetry
from security_intelligence.telemetry.generator import generate_telemetry
from security_intelligence.validation.validator import (
    MissingProcessedDatasetsError,
    validate_telemetry,
)


def test_validation_pipeline_creates_json_summary_and_markdown_report(tmp_path: Path) -> None:
    raw_dir = tmp_path / "raw"
    processed_dir = tmp_path / "processed"
    summary_path = tmp_path / "outputs" / "data_quality_summary.json"
    report_path = tmp_path / "reports" / "data_quality_report.md"
    generate_telemetry(raw_dir, days=7, users=8, seed=123)
    ingest_telemetry(raw_dir, processed_dir, tmp_path / "outputs" / "ingestion_summary.json")

    summary = validate_telemetry(processed_dir, summary_path, report_path)

    assert summary_path.exists()
    assert report_path.exists()
    saved_summary = json.loads(summary_path.read_text(encoding="utf-8"))
    report = report_path.read_text(encoding="utf-8")
    assert len(saved_summary["datasets_validated"]) == 6
    assert "overall_data_quality_score" in saved_summary
    assert "# Data Quality Report" in report
    assert summary["overall_data_quality_score"] == saved_summary["overall_data_quality_score"]


def test_validation_pipeline_reports_missing_processed_files(tmp_path: Path) -> None:
    processed_dir = tmp_path / "processed"
    processed_dir.mkdir()

    with pytest.raises(MissingProcessedDatasetsError, match="identity_events.csv"):
        validate_telemetry(
            processed_dir,
            tmp_path / "summary.json",
            tmp_path / "report.md",
        )

