"""Evidence manifest helpers."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

EVIDENCE_ARTIFACTS = [
    {
        "artifact_name": "Ingestion Summary",
        "artifact_type": "json",
        "path": "outputs/ingestion_summary.json",
        "purpose": "Record counts and processed file lineage for telemetry ingestion.",
        "related_stage": "ingestion",
    },
    {
        "artifact_name": "Data Quality Summary",
        "artifact_type": "json",
        "path": "outputs/data_quality_summary.json",
        "purpose": "Machine-readable validation results and data quality score.",
        "related_stage": "validation",
    },
    {
        "artifact_name": "Security Findings",
        "artifact_type": "json",
        "path": "outputs/security_findings.json",
        "purpose": "Deterministic threat detection findings and MITRE mappings.",
        "related_stage": "threat_detection",
    },
    {
        "artifact_name": "Identity Governance Findings",
        "artifact_type": "json",
        "path": "outputs/identity_governance_findings.json",
        "purpose": "Identity governance findings and access review evidence.",
        "related_stage": "identity_governance",
    },
    {
        "artifact_name": "Risk Scores",
        "artifact_type": "json",
        "path": "outputs/risk_scores.json",
        "purpose": "Entity risk scoring records and risk band distribution.",
        "related_stage": "risk_scoring",
    },
    {
        "artifact_name": "Risk Scores CSV",
        "artifact_type": "csv",
        "path": "outputs/risk_scores.csv",
        "purpose": "Flattened risk score export for analytics and reporting.",
        "related_stage": "risk_scoring",
    },
    {
        "artifact_name": "Identity Review CSV",
        "artifact_type": "csv",
        "path": "outputs/identity_review.csv",
        "purpose": "Flattened identity review evidence for governance workflows.",
        "related_stage": "identity_governance",
    },
    {
        "artifact_name": "Data Quality Report",
        "artifact_type": "markdown",
        "path": "reports/data_quality_report.md",
        "purpose": "Human-readable data quality evidence report.",
        "related_stage": "validation",
    },
    {
        "artifact_name": "Security Findings Report",
        "artifact_type": "markdown",
        "path": "reports/security_findings_report.md",
        "purpose": "Human-readable detection findings report.",
        "related_stage": "threat_detection",
    },
    {
        "artifact_name": "Identity Governance Report",
        "artifact_type": "markdown",
        "path": "reports/identity_governance_report.md",
        "purpose": "Human-readable identity governance report.",
        "related_stage": "identity_governance",
    },
    {
        "artifact_name": "Risk Scoring Report",
        "artifact_type": "markdown",
        "path": "reports/risk_scoring_report.md",
        "purpose": "Human-readable risk scoring report.",
        "related_stage": "risk_scoring",
    },
]


def build_evidence_manifest(
    *,
    outputs_dir: str | Path,
    reports_dir: str | Path,
) -> dict[str, Any]:
    """Build an evidence pack manifest for operational and audit outputs."""
    outputs_path = Path(outputs_dir)
    reports_path = Path(reports_dir)
    artifacts = []
    for artifact in EVIDENCE_ARTIFACTS:
        artifact_path = Path(artifact["path"])
        if artifact_path.parts[0] == "outputs":
            resolved_path = outputs_path / Path(*artifact_path.parts[1:])
        elif artifact_path.parts[0] == "reports":
            resolved_path = reports_path / Path(*artifact_path.parts[1:])
        else:
            resolved_path = artifact_path
        artifacts.append(
            {
                **artifact,
                "path": str(resolved_path),
                "exists": resolved_path.exists(),
            }
        )

    return {
        "generated_timestamp": datetime.now(UTC).isoformat(),
        "evidence_pack_name": "Azure Enterprise Security Intelligence Operational Evidence Pack",
        "artifacts": artifacts,
        "control_alignment": {
            "logging_and_monitoring": [
                "Ingestion Summary",
                "Data Quality Summary",
                "Risk Scores",
            ],
            "incident_response": [
                "Security Findings",
                "Security Findings Report",
            ],
            "identity_governance": [
                "Identity Governance Findings",
                "Identity Review CSV",
                "Identity Governance Report",
            ],
            "risk_management": [
                "Risk Scores",
                "Risk Scores CSV",
                "Risk Scoring Report",
            ],
            "evidence_generation": [
                artifact["artifact_name"] for artifact in artifacts
            ],
        },
    }

