import json
from pathlib import Path

from security_intelligence.detections.engine import run_detections
from security_intelligence.ingestion.pipeline import ingest_telemetry
from security_intelligence.telemetry.generator import generate_telemetry


def test_detection_engine_creates_json_and_markdown_outputs(tmp_path: Path) -> None:
    raw_dir = tmp_path / "raw"
    processed_dir = tmp_path / "processed"
    output_path = tmp_path / "outputs" / "security_findings.json"
    report_path = tmp_path / "reports" / "security_findings_report.md"
    generate_telemetry(raw_dir, days=30, users=50, seed=42)
    ingest_telemetry(raw_dir, processed_dir, tmp_path / "outputs" / "ingestion_summary.json")

    summary = run_detections(processed_dir, output_path, report_path)

    assert output_path.exists()
    assert report_path.exists()
    saved_summary = json.loads(output_path.read_text(encoding="utf-8"))
    assert saved_summary["total_findings"] == summary["total_findings"]
    assert saved_summary["total_findings"] > 0
    assert "# Security Findings Report" in report_path.read_text(encoding="utf-8")
    first_finding = saved_summary["findings"][0]
    assert first_finding["mitre_tactic"]
    assert first_finding["mitre_technique"]
    assert first_finding["evidence"]


def test_detection_engine_skips_disabled_rules(tmp_path: Path) -> None:
    raw_dir = tmp_path / "raw"
    processed_dir = tmp_path / "processed"
    output_path = tmp_path / "security_findings.json"
    report_path = tmp_path / "security_findings_report.md"
    config_path = tmp_path / "detection_rules.yaml"
    generate_telemetry(raw_dir, days=30, users=50, seed=42)
    ingest_telemetry(raw_dir, processed_dir, tmp_path / "ingestion_summary.json")
    config_path.write_text(
        """
detection_rules:
  - rule_id: DET-001
    rule_name: Impossible travel
    enabled: false
    severity: high
    mitre_tactic: Initial Access
    mitre_technique: Valid Accounts
    window_minutes: 120
""",
        encoding="utf-8",
    )

    summary = run_detections(processed_dir, output_path, report_path, config_path=config_path)

    assert summary["rules_executed"] == []
    assert summary["findings"] == []

