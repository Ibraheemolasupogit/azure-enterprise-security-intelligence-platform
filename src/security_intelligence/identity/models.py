"""Identity governance finding model helpers."""

from __future__ import annotations

from typing import Any

SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}


def build_governance_finding(
    *,
    check_timestamp: str,
    check_id: str,
    check_name: str,
    severity: str,
    user_id: str,
    user_principal_name: str,
    identity_type: str,
    department: str,
    role: str,
    finding_category: str,
    description: str,
    recommended_action: str,
    evidence: dict[str, Any],
    source_datasets: list[str],
) -> dict[str, Any]:
    """Build a structured identity governance finding dictionary."""
    return {
        "governance_finding_id": "",
        "check_timestamp": check_timestamp,
        "check_id": check_id,
        "check_name": check_name,
        "severity": severity,
        "user_id": user_id,
        "user_principal_name": user_principal_name,
        "identity_type": identity_type,
        "department": department,
        "role": role,
        "finding_category": finding_category,
        "description": description,
        "recommended_action": recommended_action,
        "evidence": evidence,
        "source_datasets": source_datasets,
    }

