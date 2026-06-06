"""Deterministic risk scoring helpers."""

from __future__ import annotations

from typing import Any

DEFAULT_SEVERITY_WEIGHTS = {
    "critical": 30,
    "high": 20,
    "medium": 10,
    "low": 5,
}

DEFAULT_GOVERNANCE_CATEGORY_WEIGHTS = {
    "mfa_gap": 15,
    "risky_privilege_assignment": 25,
    "privileged_cloud_activity": 25,
    "dormant_privileged_account": 20,
    "guest_exposure": 15,
    "role_sprawl": 10,
    "dormant_user": 5,
}

DEFAULT_RISK_BANDS = {
    "low": {"min": 0, "max": 24},
    "medium": {"min": 25, "max": 49},
    "high": {"min": 50, "max": 74},
    "critical": {"min": 75, "max": 100},
}

DEFAULT_PRIVILEGED_ROLES = {
    "global administrator",
    "global admin",
    "security administrator",
    "security operator",
    "privileged role administrator",
    "owner",
    "contributor",
    "user access administrator",
}


def score_severities(
    severity_counts: dict[str, int],
    severity_weights: dict[str, int],
) -> tuple[int, list[str]]:
    """Calculate weighted score contribution from severity counts."""
    score = 0
    factors = []
    for severity, count in sorted(severity_counts.items()):
        if count <= 0:
            continue
        weight = severity_weights.get(severity, 0)
        contribution = count * weight
        score += contribution
        factors.append(f"{count} {severity} findings (+{contribution})")
    return score, factors


def score_governance_categories(
    category_counts: dict[str, int],
    category_weights: dict[str, int],
) -> tuple[int, list[str]]:
    """Calculate weighted score contribution from governance categories."""
    score = 0
    factors = []
    for category, count in sorted(category_counts.items()):
        if count <= 0:
            continue
        weight = category_weights.get(category, 0)
        contribution = count * weight
        score += contribution
        factors.append(f"{count} {category} findings (+{contribution})")
    return score, factors


def is_privileged_role(role: str, privileged_roles: set[str] | None = None) -> bool:
    """Return whether a role should receive the privileged-role modifier."""
    roles = privileged_roles or DEFAULT_PRIVILEGED_ROLES
    normalized_role = role.lower().replace("administrator", "admin")
    normalized_roles = {value.lower().replace("administrator", "admin") for value in roles}
    return normalized_role in normalized_roles


def assign_risk_band(risk_score: int, risk_bands: dict[str, dict[str, int]]) -> str:
    """Assign a risk band for a numeric risk score."""
    for band, bounds in risk_bands.items():
        if int(bounds["min"]) <= risk_score <= int(bounds["max"]):
            return band
    return "critical" if risk_score > 100 else "low"


def cap_score(score: int, score_cap: int = 100) -> int:
    """Cap a risk score at the configured maximum."""
    return min(score, score_cap)


def recommended_action_for_band(risk_band: str) -> str:
    """Return a deterministic recommended action for a risk band."""
    if risk_band == "critical":
        return "Prioritize immediate investigation and executive visibility."
    if risk_band == "high":
        return "Review within the next operational cycle and reduce exposure."
    if risk_band == "medium":
        return "Track for governance review and validate compensating controls."
    return "Monitor as part of routine security operations."


def scoring_weights_summary(
    severity_weights: dict[str, int],
    category_weights: dict[str, int],
    score_cap: int,
    risk_bands: dict[str, dict[str, int]],
) -> dict[str, Any]:
    """Build a serializable scoring weights summary."""
    return {
        "severity_weights": severity_weights,
        "governance_category_weights": category_weights,
        "modifiers": {
            "privileged_role": 10,
            "multiple_finding_categories": 10,
            "security_and_governance_overlap": 15,
        },
        "score_cap": score_cap,
        "risk_bands": risk_bands,
    }

