from pathlib import Path

from security_intelligence.detections.engine import run_detections
from security_intelligence.identity.engine import run_identity_checks
from security_intelligence.ingestion.pipeline import ingest_telemetry
from security_intelligence.monitoring.engine import monitor_platform
from security_intelligence.risk.engine import score_risk
from security_intelligence.telemetry.generator import generate_telemetry
from security_intelligence.validation.validator import validate_telemetry


def build_full_evidence_chain(tmp_path: Path) -> tuple[Path, Path]:
    """Build the local evidence chain required by copilot tests."""
    raw_dir = tmp_path / "raw"
    processed_dir = tmp_path / "processed"
    outputs = tmp_path / "outputs"
    reports = tmp_path / "reports"
    generate_telemetry(raw_dir, days=30, users=50, seed=42)
    ingest_telemetry(raw_dir, processed_dir, outputs / "ingestion_summary.json")
    validate_telemetry(processed_dir, outputs / "data_quality_summary.json", reports / "dq.md")
    run_detections(processed_dir, outputs / "security_findings.json", reports / "sec.md")
    run_identity_checks(
        processed_dir,
        outputs / "identity_governance_findings.json",
        outputs / "identity_review.csv",
        reports / "identity.md",
    )
    score_risk(
        outputs / "security_findings.json",
        outputs / "identity_governance_findings.json",
        outputs / "data_quality_summary.json",
        processed_dir,
        outputs / "risk_scores.json",
        outputs / "risk_scores.csv",
        reports / "risk.md",
    )
    monitor_platform(
        outputs,
        reports,
        outputs / "operational_health_summary.json",
        outputs / "evidence_manifest.json",
        reports / "operational_evidence_report.md",
    )
    return outputs, reports

