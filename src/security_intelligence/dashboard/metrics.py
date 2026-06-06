"""Executive metric builders for dashboard exports."""

from __future__ import annotations

from typing import Any

REQUIRED_METRICS = [
    "total_records_ingested",
    "data_quality_score",
    "total_security_findings",
    "critical_security_findings",
    "total_identity_governance_findings",
    "critical_high_identity_governance_findings",
    "total_entities_scored",
    "critical_risk_entities",
    "operational_health_status",
    "evidence_artifacts_available",
    "copilot_context_generated",
]


def build_executive_metrics(payloads: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Build flattened executive metrics from platform output payloads."""
    ingestion = payloads.get("ingestion", {})
    validation = payloads.get("validation", {})
    security = payloads.get("security", {})
    identity = payloads.get("identity", {})
    risk = payloads.get("risk", {})
    health = payloads.get("health", {})
    manifest = payloads.get("manifest", {})
    copilot = payloads.get("copilot", {})

    security_severity = security.get("findings_by_severity", {})
    identity_severity = identity.get("findings_by_severity", {})
    risk_bands = risk.get("risk_band_counts", {})
    artifacts_available = sum(
        1 for artifact in manifest.get("artifacts", []) if artifact.get("exists")
    )

    return [
        _metric(
            "total_records_ingested",
            ingestion.get("total_records_ingested", 0),
            "pipeline",
            "good",
            "Total records ingested from synthetic raw telemetry.",
            "outputs/ingestion_summary.json",
        ),
        _metric(
            "data_quality_score",
            validation.get("overall_data_quality_score", 0),
            "quality",
            "good" if float(validation.get("overall_data_quality_score", 0)) >= 90 else "warning",
            "Overall validation data quality score.",
            "outputs/data_quality_summary.json",
        ),
        _metric(
            "total_security_findings",
            security.get("total_findings", 0),
            "security",
            "warning" if int(security.get("total_findings", 0)) else "good",
            "Total deterministic security findings.",
            "outputs/security_findings.json",
        ),
        _metric(
            "critical_security_findings",
            security_severity.get("critical", 0),
            "security",
            "warning" if int(security_severity.get("critical", 0)) else "good",
            "Critical security findings requiring SOC review.",
            "outputs/security_findings.json",
        ),
        _metric(
            "total_identity_governance_findings",
            identity.get("total_findings", 0),
            "identity",
            "warning" if int(identity.get("total_findings", 0)) else "good",
            "Total identity governance findings.",
            "outputs/identity_governance_findings.json",
        ),
        _metric(
            "critical_high_identity_governance_findings",
            int(identity_severity.get("critical", 0)) + int(identity_severity.get("high", 0)),
            "identity",
            "warning",
            "Critical and high identity governance findings.",
            "outputs/identity_governance_findings.json",
        ),
        _metric(
            "total_entities_scored",
            risk.get("total_entities_scored", 0),
            "risk",
            "good",
            "Total entities with deterministic risk scores.",
            "outputs/risk_scores.json",
        ),
        _metric(
            "critical_risk_entities",
            risk_bands.get("critical", 0),
            "risk",
            "warning" if int(risk_bands.get("critical", 0)) else "good",
            "Entities in the critical risk band.",
            "outputs/risk_scores.json",
        ),
        _metric(
            "operational_health_status",
            health.get("overall_status", "unknown"),
            "operations",
            health.get("overall_status", "unknown"),
            "Overall local platform operational health status.",
            "outputs/operational_health_summary.json",
        ),
        _metric(
            "evidence_artifacts_available",
            artifacts_available,
            "evidence",
            "good" if artifacts_available else "warning",
            "Evidence artifacts available in the local manifest.",
            "outputs/evidence_manifest.json",
        ),
        _metric(
            "copilot_context_generated",
            bool(copilot.get("incident_context_id")),
            "copilot",
            "good" if copilot.get("incident_context_id") else "warning",
            "Whether local simulated copilot context was generated.",
            "outputs/copilot_context.json",
        ),
    ]


def _metric(
    name: str,
    value: Any,
    category: str,
    status: str,
    description: str,
    source_artifact: str,
) -> dict[str, Any]:
    return {
        "metric_name": name,
        "metric_value": value,
        "metric_category": category,
        "metric_status": status,
        "description": description,
        "source_artifact": source_artifact,
    }
