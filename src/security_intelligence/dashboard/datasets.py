"""Dashboard dataset shaping helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pandas as pd


def load_dashboard_payloads(outputs_dir: str | Path) -> dict[str, dict[str, Any]]:
    """Load dashboard source payloads, returning empty payloads for optional missing files."""
    outputs_path = Path(outputs_dir)
    return {
        "ingestion": _load_json(outputs_path / "ingestion_summary.json"),
        "validation": _load_json(outputs_path / "data_quality_summary.json"),
        "security": _load_json(outputs_path / "security_findings.json"),
        "identity": _load_json(outputs_path / "identity_governance_findings.json"),
        "risk": _load_json(outputs_path / "risk_scores.json"),
        "health": _load_json(outputs_path / "operational_health_summary.json"),
        "manifest": _load_json(outputs_path / "evidence_manifest.json"),
        "copilot": _load_json(outputs_path / "copilot_context.json"),
    }


def security_findings_dataframe(payloads: dict[str, dict[str, Any]]) -> pd.DataFrame:
    """Create a dashboard-ready security findings DataFrame."""
    rows = []
    for finding in payloads.get("security", {}).get("findings", []):
        rows.append(
            {
                "finding_id": finding.get("finding_id"),
                "rule_name": finding.get("rule_name"),
                "severity": finding.get("severity"),
                "entity_type": finding.get("entity_type"),
                "entity_id": finding.get("entity_id"),
                "user_id": finding.get("user_id"),
                "source_dataset": finding.get("source_dataset"),
                "mitre_tactic": finding.get("mitre_tactic"),
                "mitre_technique": finding.get("mitre_technique"),
                "recommended_action": finding.get("recommended_action"),
            }
        )
    return pd.DataFrame(rows)


def identity_governance_dataframe(payloads: dict[str, dict[str, Any]]) -> pd.DataFrame:
    """Create a dashboard-ready identity governance DataFrame."""
    rows = []
    for finding in payloads.get("identity", {}).get("findings", []):
        rows.append(
            {
                "governance_finding_id": finding.get("governance_finding_id"),
                "check_name": finding.get("check_name"),
                "severity": finding.get("severity"),
                "user_id": finding.get("user_id"),
                "user_principal_name": finding.get("user_principal_name"),
                "department": finding.get("department"),
                "role": finding.get("role"),
                "identity_type": finding.get("identity_type"),
                "finding_category": finding.get("finding_category"),
                "recommended_action": finding.get("recommended_action"),
            }
        )
    return pd.DataFrame(rows)


def risk_scores_dataframe(payloads: dict[str, dict[str, Any]]) -> pd.DataFrame:
    """Create a dashboard-ready risk scores DataFrame."""
    rows = []
    for record in payloads.get("risk", {}).get("risk_scores", []):
        rows.append(
            {
                "risk_id": record.get("risk_id"),
                "entity_type": record.get("entity_type"),
                "entity_id": record.get("entity_id"),
                "user_id": record.get("user_id"),
                "user_principal_name": record.get("user_principal_name"),
                "department": record.get("department"),
                "role": record.get("role"),
                "risk_score": record.get("risk_score"),
                "risk_band": record.get("risk_band"),
                "security_finding_count": record.get("security_finding_count"),
                "governance_finding_count": record.get("governance_finding_count"),
                "recommended_action": record.get("recommended_action"),
            }
        )
    return pd.DataFrame(rows)


def operational_health_dataframe(payloads: dict[str, dict[str, Any]]) -> pd.DataFrame:
    """Create a dashboard-ready operational health DataFrame."""
    rows = []
    for result in payloads.get("health", {}).get("stage_results", []):
        rows.append(
            {
                "pipeline_stage": result.get("pipeline_stage"),
                "status": result.get("status"),
                "artifact_exists": result.get("artifact_exists"),
                "record_count": result.get("record_count"),
                "warning_count": len(result.get("warnings", [])),
                "failure_count": len(result.get("failures", [])),
                "recommended_action": result.get("recommended_action"),
            }
        )
    return pd.DataFrame(rows)


def evidence_manifest_dataframe(payloads: dict[str, dict[str, Any]]) -> pd.DataFrame:
    """Create a dashboard-ready evidence manifest DataFrame."""
    rows = []
    for artifact in payloads.get("manifest", {}).get("artifacts", []):
        rows.append(
            {
                "artifact_name": artifact.get("artifact_name"),
                "artifact_type": artifact.get("artifact_type"),
                "path": artifact.get("path"),
                "exists": artifact.get("exists"),
                "purpose": artifact.get("purpose"),
                "related_stage": artifact.get("related_stage"),
            }
        )
    return pd.DataFrame(rows)


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))

