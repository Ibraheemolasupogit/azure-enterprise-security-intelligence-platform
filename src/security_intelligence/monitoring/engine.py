"""Monitoring and operational evidence engine."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from security_intelligence.monitoring.evidence import build_evidence_manifest
from security_intelligence.monitoring.health import (
    check_artifact_stage,
    load_json_if_exists,
)
from security_intelligence.monitoring.summary import (
    write_evidence_manifest,
    write_operational_evidence_report,
    write_operational_health_summary,
)
from security_intelligence.paths import OUTPUT_DIR, REPORTS_DIR


def monitor_platform(
    outputs_dir: str | Path = OUTPUT_DIR,
    reports_dir: str | Path = REPORTS_DIR,
    health_path: str | Path = OUTPUT_DIR / "operational_health_summary.json",
    manifest_path: str | Path = OUTPUT_DIR / "evidence_manifest.json",
    report_path: str | Path = REPORTS_DIR / "operational_evidence_report.md",
    freshness_hours: int = 24,
    quality_threshold: float = 90,
) -> dict[str, Any]:
    """Run local operational monitoring and write evidence outputs."""
    outputs_path = Path(outputs_dir)
    reports_path = Path(reports_dir)
    monitoring_timestamp = datetime.now(UTC).isoformat()

    ingestion = load_json_if_exists(outputs_path / "ingestion_summary.json")
    validation = load_json_if_exists(outputs_path / "data_quality_summary.json")
    security = load_json_if_exists(outputs_path / "security_findings.json")
    identity = load_json_if_exists(outputs_path / "identity_governance_findings.json")
    risk = load_json_if_exists(outputs_path / "risk_scores.json")

    stage_results = [
        _telemetry_generation_stage(outputs_path, monitoring_timestamp, freshness_hours, ingestion),
        _ingestion_stage(outputs_path, monitoring_timestamp, freshness_hours, ingestion),
        _validation_stage(
            outputs_path,
            monitoring_timestamp,
            freshness_hours,
            validation,
            quality_threshold,
        ),
        _security_stage(outputs_path, monitoring_timestamp, freshness_hours, security),
        _identity_stage(outputs_path, monitoring_timestamp, freshness_hours, identity),
        _risk_stage(outputs_path, monitoring_timestamp, freshness_hours, risk),
    ]
    warnings = [
        warning
        for result in stage_results
        for warning in result["warnings"]
    ]
    failures = [
        failure
        for result in stage_results
        for failure in result["failures"]
    ]
    key_metrics = _key_metrics(ingestion, validation, security, identity, risk)
    overall_status = "failed" if failures else "warning" if warnings else "passed"
    health_summary = {
        "monitoring_timestamp": monitoring_timestamp,
        "overall_status": overall_status,
        "stages_checked": len(stage_results),
        "stage_results": stage_results,
        "warnings": warnings,
        "failures": failures,
        "key_metrics": key_metrics,
        "recommended_next_actions": _recommended_actions(overall_status, warnings, failures),
    }
    evidence_manifest = build_evidence_manifest(outputs_dir=outputs_path, reports_dir=reports_path)

    write_operational_health_summary(health_path, health_summary)
    write_evidence_manifest(manifest_path, evidence_manifest)
    write_operational_evidence_report(report_path, health_summary, evidence_manifest)
    return {
        "health_summary": health_summary,
        "evidence_manifest": evidence_manifest,
    }


def _telemetry_generation_stage(
    outputs_path: Path,
    timestamp: str,
    freshness_hours: int,
    ingestion: dict[str, Any],
) -> dict[str, Any]:
    path = outputs_path / "ingestion_summary.json"
    record_count = ingestion.get("total_records_ingested")
    warnings = []
    if record_count == 0:
        warnings.append(
            "No ingested records found; telemetry generation may not have produced data."
        )
    return check_artifact_stage(
        stage="telemetry_generation",
        path=path,
        monitoring_timestamp=timestamp,
        freshness_hours=freshness_hours,
        record_count=record_count,
        key_metrics={"raw_to_ingested_records": record_count},
        warnings=warnings,
        recommended_action="Regenerate synthetic telemetry if record counts are unexpectedly low.",
    )


def _ingestion_stage(
    outputs_path: Path,
    timestamp: str,
    freshness_hours: int,
    ingestion: dict[str, Any],
) -> dict[str, Any]:
    path = outputs_path / "ingestion_summary.json"
    record_count = ingestion.get("total_records_ingested")
    failures = []
    if ingestion and ingestion.get("status") != "success":
        failures.append("Ingestion summary status is not success.")
    return check_artifact_stage(
        stage="ingestion",
        path=path,
        monitoring_timestamp=timestamp,
        freshness_hours=freshness_hours,
        record_count=record_count,
        key_metrics={
            "datasets_processed": len(ingestion.get("datasets", [])),
            "total_records_ingested": record_count,
        },
        failures=failures,
        recommended_action="Review ingestion summary and regenerate processed CSV files.",
    )


def _validation_stage(
    outputs_path: Path,
    timestamp: str,
    freshness_hours: int,
    validation: dict[str, Any],
    quality_threshold: float,
) -> dict[str, Any]:
    path = outputs_path / "data_quality_summary.json"
    quality_score = validation.get("overall_data_quality_score")
    warnings = []
    if quality_score is not None and float(quality_score) < quality_threshold:
        warnings.append(
            f"Data quality score {quality_score} is below threshold {quality_threshold}."
        )
    return check_artifact_stage(
        stage="validation",
        path=path,
        monitoring_timestamp=timestamp,
        freshness_hours=freshness_hours,
        record_count=len(validation.get("datasets_validated", [])) if validation else None,
        key_metrics={"overall_data_quality_score": quality_score},
        warnings=warnings,
        recommended_action="Review data quality report and fix failed validation checks.",
    )


def _security_stage(
    outputs_path: Path,
    timestamp: str,
    freshness_hours: int,
    security: dict[str, Any],
) -> dict[str, Any]:
    path = outputs_path / "security_findings.json"
    findings_by_severity = security.get("findings_by_severity", {})
    critical = int(findings_by_severity.get("critical", 0))
    warnings = []
    if critical > 0:
        warnings.append(f"Critical security findings present: {critical}")
    return check_artifact_stage(
        stage="threat_detection",
        path=path,
        monitoring_timestamp=timestamp,
        freshness_hours=freshness_hours,
        record_count=security.get("total_findings"),
        key_metrics={
            "total_findings": security.get("total_findings"),
            "findings_by_severity": findings_by_severity,
        },
        warnings=warnings,
        recommended_action="Triage critical and high security findings.",
    )


def _identity_stage(
    outputs_path: Path,
    timestamp: str,
    freshness_hours: int,
    identity: dict[str, Any],
) -> dict[str, Any]:
    path = outputs_path / "identity_governance_findings.json"
    findings_by_severity = identity.get("findings_by_severity", {})
    critical_high = int(findings_by_severity.get("critical", 0)) + int(
        findings_by_severity.get("high", 0)
    )
    warnings = []
    if critical_high > 0:
        warnings.append(f"Critical/high identity governance findings present: {critical_high}")
    return check_artifact_stage(
        stage="identity_governance",
        path=path,
        monitoring_timestamp=timestamp,
        freshness_hours=freshness_hours,
        record_count=identity.get("total_findings"),
        key_metrics={
            "total_findings": identity.get("total_findings"),
            "findings_by_category": identity.get("findings_by_category", {}),
        },
        warnings=warnings,
        recommended_action="Review high-risk identity governance findings and access reviews.",
    )


def _risk_stage(
    outputs_path: Path,
    timestamp: str,
    freshness_hours: int,
    risk: dict[str, Any],
) -> dict[str, Any]:
    path = outputs_path / "risk_scores.json"
    band_counts = risk.get("risk_band_counts", {})
    critical = int(band_counts.get("critical", 0))
    warnings = []
    if critical > 0:
        warnings.append(f"Critical risk entities present: {critical}")
    return check_artifact_stage(
        stage="risk_scoring",
        path=path,
        monitoring_timestamp=timestamp,
        freshness_hours=freshness_hours,
        record_count=risk.get("total_entities_scored"),
        key_metrics={
            "total_entities_scored": risk.get("total_entities_scored"),
            "risk_band_counts": band_counts,
        },
        warnings=warnings,
        recommended_action="Prioritize critical risk entities for operational review.",
    )


def _key_metrics(
    ingestion: dict[str, Any],
    validation: dict[str, Any],
    security: dict[str, Any],
    identity: dict[str, Any],
    risk: dict[str, Any],
) -> dict[str, Any]:
    security_severity = security.get("findings_by_severity", {})
    identity_severity = identity.get("findings_by_severity", {})
    risk_bands = risk.get("risk_band_counts", {})
    return {
        "records_ingested": ingestion.get("total_records_ingested"),
        "datasets_validated": len(validation.get("datasets_validated", [])),
        "overall_data_quality_score": validation.get("overall_data_quality_score"),
        "security_findings_total": security.get("total_findings"),
        "critical_security_findings": int(security_severity.get("critical", 0)),
        "identity_findings_total": identity.get("total_findings"),
        "critical_high_identity_findings": int(identity_severity.get("critical", 0))
        + int(identity_severity.get("high", 0)),
        "entities_scored": risk.get("total_entities_scored"),
        "critical_risk_entities": int(risk_bands.get("critical", 0)),
    }


def _recommended_actions(
    overall_status: str,
    warnings: list[str],
    failures: list[str],
) -> list[str]:
    actions = []
    if failures:
        actions.append("Regenerate missing or failed pipeline artifacts before audit use.")
    if warnings:
        actions.append(
            "Review warning-level operational risk signals with SOC and governance owners."
        )
    if overall_status == "passed":
        actions.append("Preserve evidence pack outputs for reporting and audit readiness.")
    else:
        actions.append("Refresh the full local pipeline after remediation and rerun monitoring.")
    actions.append("Use the evidence manifest as the index for local operational evidence.")
    return actions
