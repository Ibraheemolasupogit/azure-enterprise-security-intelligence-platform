import json
from pathlib import Path

import pandas as pd

from security_intelligence.identity.engine import run_identity_checks
from security_intelligence.ingestion.pipeline import ingest_telemetry
from security_intelligence.telemetry.generator import generate_telemetry


def test_identity_engine_creates_json_review_csv_and_report(tmp_path: Path) -> None:
    raw_dir = tmp_path / "raw"
    processed_dir = tmp_path / "processed"
    output_path = tmp_path / "outputs" / "identity_governance_findings.json"
    review_path = tmp_path / "outputs" / "identity_review.csv"
    report_path = tmp_path / "reports" / "identity_governance_report.md"
    generate_telemetry(raw_dir, days=30, users=50, seed=42)
    ingest_telemetry(raw_dir, processed_dir, tmp_path / "outputs" / "ingestion_summary.json")

    summary = run_identity_checks(
        processed_dir,
        output_path,
        review_path,
        report_path,
        inactivity_days=30,
    )

    assert output_path.exists()
    assert review_path.exists()
    assert report_path.exists()
    saved_summary = json.loads(output_path.read_text(encoding="utf-8"))
    review = pd.read_csv(review_path)
    report = report_path.read_text(encoding="utf-8")
    assert saved_summary["total_findings"] == summary["total_findings"]
    assert saved_summary["total_findings"] > 0
    assert not review.empty
    assert "# Identity Governance Report" in report
    assert saved_summary["findings"][0]["evidence"]
    assert saved_summary["findings"][0]["source_datasets"]

