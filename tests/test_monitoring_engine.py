import json
from pathlib import Path

from security_intelligence.monitoring.engine import monitor_platform


def test_data_quality_below_threshold_produces_warning(tmp_path: Path) -> None:
    outputs = tmp_path / "outputs"
    reports = tmp_path / "reports"
    _write_minimal_outputs(outputs, data_quality_score=70)

    result = monitor_platform(outputs_dir=outputs, reports_dir=reports, quality_threshold=90)

    warnings = result["health_summary"]["warnings"]
    assert any("Data quality score" in warning for warning in warnings)


def test_critical_security_identity_and_risk_produce_warnings(tmp_path: Path) -> None:
    outputs = tmp_path / "outputs"
    reports = tmp_path / "reports"
    _write_minimal_outputs(outputs)

    result = monitor_platform(outputs_dir=outputs, reports_dir=reports)

    warnings = result["health_summary"]["warnings"]
    assert any("Critical security findings" in warning for warning in warnings)
    assert any("Critical/high identity governance" in warning for warning in warnings)
    assert any("Critical risk entities" in warning for warning in warnings)


def test_monitoring_engine_creates_outputs(tmp_path: Path) -> None:
    outputs = tmp_path / "outputs"
    reports = tmp_path / "reports"
    health_path = outputs / "operational_health_summary.json"
    manifest_path = outputs / "evidence_manifest.json"
    report_path = reports / "operational_evidence_report.md"
    _write_minimal_outputs(outputs)

    result = monitor_platform(
        outputs_dir=outputs,
        reports_dir=reports,
        health_path=health_path,
        manifest_path=manifest_path,
        report_path=report_path,
    )

    assert health_path.exists()
    assert manifest_path.exists()
    assert report_path.exists()
    saved_health = json.loads(health_path.read_text(encoding="utf-8"))
    saved_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert saved_health["stages_checked"] == 6
    assert saved_manifest["artifacts"]
    assert "# Operational Evidence Report" in report_path.read_text(encoding="utf-8")
    assert result["health_summary"]["overall_status"] == "warning"


def _write_minimal_outputs(outputs: Path, data_quality_score: float = 95) -> None:
    outputs.mkdir(parents=True, exist_ok=True)
    (outputs / "ingestion_summary.json").write_text(
        json.dumps({"status": "success", "total_records_ingested": 10, "datasets": [{}]}),
        encoding="utf-8",
    )
    (outputs / "data_quality_summary.json").write_text(
        json.dumps(
            {
                "overall_data_quality_score": data_quality_score,
                "datasets_validated": [{"dataset_name": "identity_events", "status": "passed"}],
            }
        ),
        encoding="utf-8",
    )
    (outputs / "security_findings.json").write_text(
        json.dumps({"total_findings": 2, "findings_by_severity": {"critical": 1}}),
        encoding="utf-8",
    )
    (outputs / "identity_governance_findings.json").write_text(
        json.dumps(
            {
                "total_findings": 2,
                "findings_by_severity": {"high": 1},
                "findings_by_category": {"mfa_gap": 1},
            }
        ),
        encoding="utf-8",
    )
    (outputs / "risk_scores.json").write_text(
        json.dumps({"total_entities_scored": 2, "risk_band_counts": {"critical": 1}}),
        encoding="utf-8",
    )

