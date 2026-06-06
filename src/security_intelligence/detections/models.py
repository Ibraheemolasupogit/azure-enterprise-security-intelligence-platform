"""Finding model helpers for deterministic detections."""

from __future__ import annotations

from typing import Any

SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}


def build_finding(
    *,
    detection_timestamp: str,
    rule_id: str,
    rule_name: str,
    severity: str,
    confidence: float,
    entity_type: str,
    entity_id: str,
    user_id: str | None,
    source_dataset: str,
    event_id: str,
    description: str,
    mitre_tactic: str,
    mitre_technique: str,
    recommended_action: str,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    """Build a structured security finding dictionary."""
    return {
        "finding_id": "",
        "detection_timestamp": detection_timestamp,
        "rule_id": rule_id,
        "rule_name": rule_name,
        "severity": severity,
        "confidence": confidence,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "user_id": user_id,
        "source_dataset": source_dataset,
        "event_id": event_id,
        "description": description,
        "mitre_tactic": mitre_tactic,
        "mitre_technique": mitre_technique,
        "recommended_action": recommended_action,
        "evidence": evidence,
    }

