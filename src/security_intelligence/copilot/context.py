"""Investigation context builder for the local simulated copilot."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def build_investigation_context(
    outputs_dir: str | Path,
    *,
    max_security_findings: int = 5,
    max_identity_findings: int = 5,
    max_risk_entities: int = 10,
) -> dict[str, Any]:
    """Load platform outputs and build deterministic investigation context."""
    outputs_path = Path(outputs_dir)
    security = _load_required_json(outputs_path / "security_findings.json")
    identity = _load_required_json(outputs_path / "identity_governance_findings.json")
    risk = _load_required_json(outputs_path / "risk_scores.json")
    health = _load_required_json(outputs_path / "operational_health_summary.json")
    manifest = _load_required_json(outputs_path / "evidence_manifest.json")
    generated_timestamp = datetime.now(UTC).isoformat()

    context = {
        "generated_timestamp": generated_timestamp,
        "incident_context_id": _incident_context_id(security, identity, risk),
        "source_inputs": {
            "security_findings": str(outputs_path / "security_findings.json"),
            "identity_governance_findings": str(
                outputs_path / "identity_governance_findings.json"
            ),
            "risk_scores": str(outputs_path / "risk_scores.json"),
            "operational_health": str(outputs_path / "operational_health_summary.json"),
            "evidence_manifest": str(outputs_path / "evidence_manifest.json"),
        },
        "key_metrics": {
            "security_findings_total": security.get("total_findings", 0),
            "identity_findings_total": identity.get("total_findings", 0),
            "entities_scored": risk.get("total_entities_scored", 0),
            "overall_health_status": health.get("overall_status", "unknown"),
            "warnings": len(health.get("warnings", [])),
            "failures": len(health.get("failures", [])),
            "critical_risk_entities": risk.get("risk_band_counts", {}).get("critical", 0),
        },
        "top_security_findings": _top_security_findings(
            security.get("findings", []), max_security_findings
        ),
        "top_identity_findings": _top_identity_findings(
            identity.get("findings", []), max_identity_findings
        ),
        "top_risk_entities": _top_risk_entities(
            risk.get("risk_scores", []), max_risk_entities
        ),
        "operational_health": {
            "overall_status": health.get("overall_status", "unknown"),
            "warnings": health.get("warnings", []),
            "failures": health.get("failures", []),
            "key_metrics": health.get("key_metrics", {}),
        },
        "available_evidence": [
            artifact
            for artifact in manifest.get("artifacts", [])
            if artifact.get("exists") is True
        ],
        "prompt_types_generated": [],
    }
    return context


def _top_security_findings(findings: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    selected = [
        finding
        for finding in findings
        if str(finding.get("severity", "")).lower() in {"critical", "high"}
    ]
    return selected[:limit]


def _top_identity_findings(findings: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    return sorted(
        findings,
        key=lambda finding: (
            -severity_rank.get(str(finding.get("severity", "")).lower(), 0),
            str(finding.get("user_principal_name", "")),
            str(finding.get("check_id", "")),
        ),
    )[:limit]


def _top_risk_entities(risk_scores: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    return sorted(
        risk_scores,
        key=lambda record: (-int(record.get("risk_score", 0)), str(record.get("risk_id", ""))),
    )[:limit]


def _incident_context_id(
    security: dict[str, Any],
    identity: dict[str, Any],
    risk: dict[str, Any],
) -> str:
    return (
        "CTX-"
        f"SEC{int(security.get('total_findings', 0)):03d}-"
        f"ID{int(identity.get('total_findings', 0)):03d}-"
        f"RISK{int(risk.get('total_entities_scored', 0)):03d}"
    )


def _load_required_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Required copilot input not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))

