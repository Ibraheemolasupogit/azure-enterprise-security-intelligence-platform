import json
from pathlib import Path

import pandas as pd

from security_intelligence.detections.engine import run_detections
from security_intelligence.identity.engine import run_identity_checks
from security_intelligence.ingestion.pipeline import ingest_telemetry
from security_intelligence.risk.engine import score_risk
from security_intelligence.telemetry.generator import generate_telemetry
from security_intelligence.validation.validator import validate_telemetry


def test_risk_engine_creates_json_csv_and_markdown_outputs(tmp_path: Path) -> None:
    paths = _build_evidence(tmp_path)

    summary = score_risk(
        security_findings_path=paths["security_findings"],
        identity_findings_path=paths["identity_findings"],
        data_quality_path=paths["data_quality"],
        input_dir=paths["processed_dir"],
        output_path=paths["risk_json"],
        csv_path=paths["risk_csv"],
        report_path=paths["risk_report"],
    )

    assert paths["risk_json"].exists()
    assert paths["risk_csv"].exists()
    assert paths["risk_report"].exists()
    saved_summary = json.loads(paths["risk_json"].read_text(encoding="utf-8"))
    risk_csv = pd.read_csv(paths["risk_csv"])
    report = paths["risk_report"].read_text(encoding="utf-8")
    assert saved_summary["total_entities_scored"] == summary["total_entities_scored"]
    assert saved_summary["total_entities_scored"] > 0
    assert not risk_csv.empty
    assert "# Risk Scoring Report" in report
    assert saved_summary["risk_scores"][0]["contributing_factors"]
    assert saved_summary["risk_scores"][0]["evidence_sources"]


def _build_evidence(tmp_path: Path) -> dict[str, Path]:
    raw_dir = tmp_path / "raw"
    processed_dir = tmp_path / "processed"
    outputs = tmp_path / "outputs"
    reports = tmp_path / "reports"
    generate_telemetry(raw_dir, days=30, users=50, seed=42)
    ingest_telemetry(raw_dir, processed_dir, outputs / "ingestion_summary.json")
    validate_telemetry(
        processed_dir,
        outputs / "data_quality_summary.json",
        reports / "data_quality_report.md",
    )
    run_detections(
        processed_dir,
        outputs / "security_findings.json",
        reports / "security_findings_report.md",
    )
    run_identity_checks(
        processed_dir,
        outputs / "identity_governance_findings.json",
        outputs / "identity_review.csv",
        reports / "identity_governance_report.md",
    )
    return {
        "processed_dir": processed_dir,
        "security_findings": outputs / "security_findings.json",
        "identity_findings": outputs / "identity_governance_findings.json",
        "data_quality": outputs / "data_quality_summary.json",
        "risk_json": outputs / "risk_scores.json",
        "risk_csv": outputs / "risk_scores.csv",
        "risk_report": reports / "risk_scoring_report.md",
    }

