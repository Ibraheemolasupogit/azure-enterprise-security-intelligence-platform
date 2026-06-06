from pathlib import Path

from security_intelligence.cli import main
from security_intelligence.detections.engine import run_detections
from security_intelligence.identity.engine import run_identity_checks
from security_intelligence.ingestion.pipeline import ingest_telemetry
from security_intelligence.telemetry.generator import generate_telemetry
from security_intelligence.validation.validator import validate_telemetry


def test_cli_score_risk_runs_successfully_after_prior_milestones(
    tmp_path: Path, capsys
) -> None:
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
        reports / "id.md",
    )

    exit_code = main(
        [
            "score-risk",
            "--security-findings-path",
            str(outputs / "security_findings.json"),
            "--identity-findings-path",
            str(outputs / "identity_governance_findings.json"),
            "--data-quality-path",
            str(outputs / "data_quality_summary.json"),
            "--input-dir",
            str(processed_dir),
            "--output-path",
            str(outputs / "risk_scores.json"),
            "--csv-path",
            str(outputs / "risk_scores.csv"),
            "--report-path",
            str(reports / "risk_scoring_report.md"),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Risk scoring complete" in captured.out
    assert "Total entities scored" in captured.out
    assert (outputs / "risk_scores.json").exists()
    assert (outputs / "risk_scores.csv").exists()
    assert (reports / "risk_scoring_report.md").exists()

