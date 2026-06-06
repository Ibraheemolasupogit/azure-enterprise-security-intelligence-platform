"""Risk score model helpers."""

from __future__ import annotations

from typing import Any

SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}


def build_risk_record(
    *,
    risk_id: str,
    scoring_timestamp: str,
    entity_type: str,
    entity_id: str,
    user_id: str | None,
    user_principal_name: str,
    department: str,
    role: str,
    risk_score: int,
    risk_band: str,
    contributing_factors: list[str],
    security_finding_count: int,
    governance_finding_count: int,
    critical_count: int,
    high_count: int,
    medium_count: int,
    low_count: int,
    recommended_action: str,
    evidence_sources: list[str],
) -> dict[str, Any]:
    """Build a structured risk score record."""
    return {
        "risk_id": risk_id,
        "scoring_timestamp": scoring_timestamp,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "user_id": user_id,
        "user_principal_name": user_principal_name,
        "department": department,
        "role": role,
        "risk_score": risk_score,
        "risk_band": risk_band,
        "contributing_factors": contributing_factors,
        "security_finding_count": security_finding_count,
        "governance_finding_count": governance_finding_count,
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "recommended_action": recommended_action,
        "evidence_sources": evidence_sources,
    }

