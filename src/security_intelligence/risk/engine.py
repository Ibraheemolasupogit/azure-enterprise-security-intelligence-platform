"""Risk scoring engine for local security intelligence evidence."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pandas as pd

from security_intelligence.config import load_yaml_config
from security_intelligence.paths import CONFIG_DIR, DATA_DIR, OUTPUT_DIR, REPORTS_DIR
from security_intelligence.risk.models import SEVERITY_ORDER, build_risk_record
from security_intelligence.risk.scoring import (
    DEFAULT_GOVERNANCE_CATEGORY_WEIGHTS,
    DEFAULT_RISK_BANDS,
    DEFAULT_SEVERITY_WEIGHTS,
    assign_risk_band,
    cap_score,
    is_privileged_role,
    recommended_action_for_band,
    score_governance_categories,
    score_severities,
    scoring_weights_summary,
)
from security_intelligence.risk.summary import (
    write_risk_csv,
    write_risk_json,
    write_risk_report,
)


def score_risk(
    security_findings_path: str | Path = OUTPUT_DIR / "security_findings.json",
    identity_findings_path: str | Path = OUTPUT_DIR / "identity_governance_findings.json",
    data_quality_path: str | Path = OUTPUT_DIR / "data_quality_summary.json",
    input_dir: str | Path = DATA_DIR / "processed",
    output_path: str | Path = OUTPUT_DIR / "risk_scores.json",
    csv_path: str | Path = OUTPUT_DIR / "risk_scores.csv",
    report_path: str | Path = REPORTS_DIR / "risk_scoring_report.md",
    config_path: str | Path = CONFIG_DIR / "platform.yaml",
) -> dict[str, Any]:
    """Calculate deterministic risk scores from findings and quality evidence."""
    config = load_yaml_config(config_path)
    settings = config.get("risk_scoring", {})
    severity_weights = _settings_dict(
        settings,
        "severity_weights",
        DEFAULT_SEVERITY_WEIGHTS,
    )
    category_weights = _settings_dict(
        settings,
        "governance_category_weights",
        DEFAULT_GOVERNANCE_CATEGORY_WEIGHTS,
    )
    score_cap = int(settings.get("score_cap", 100))
    risk_bands = settings.get("risk_bands", DEFAULT_RISK_BANDS)
    privileged_roles = set(
        role.lower()
        for role in config.get("identity_governance", {}).get("privileged_roles", [])
    )

    security_payload = _load_json(security_findings_path)
    identity_payload = _load_json(identity_findings_path)
    data_quality_context = _load_optional_json(data_quality_path)
    user_profiles = _load_user_profiles(Path(input_dir))
    scoring_timestamp = datetime.now(UTC).isoformat()

    aggregates: dict[tuple[str, str], dict[str, Any]] = defaultdict(_empty_aggregate)
    _add_security_findings(aggregates, security_payload.get("findings", []), user_profiles)
    _add_governance_findings(aggregates, identity_payload.get("findings", []), user_profiles)

    risk_records = []
    for entity_key, aggregate in aggregates.items():
        entity_type, entity_id = entity_key
        record = _score_aggregate(
            entity_type=entity_type,
            entity_id=entity_id,
            aggregate=aggregate,
            scoring_timestamp=scoring_timestamp,
            severity_weights=severity_weights,
            category_weights=category_weights,
            score_cap=score_cap,
            risk_bands=risk_bands,
            privileged_roles=privileged_roles,
        )
        risk_records.append(record)

    risk_records = _sort_and_number_records(risk_records)
    risk_band_counts = dict(Counter(record["risk_band"] for record in risk_records))
    summary = {
        "scoring_run_timestamp": scoring_timestamp,
        "total_entities_scored": len(risk_records),
        "risk_band_counts": risk_band_counts,
        "top_risks": risk_records[:10],
        "scoring_weights": scoring_weights_summary(
            severity_weights,
            category_weights,
            score_cap,
            risk_bands,
        ),
        "data_quality_context": _data_quality_context(data_quality_context),
        "risk_scores": risk_records,
    }

    write_risk_json(output_path, summary)
    write_risk_csv(csv_path, risk_records)
    write_risk_report(report_path, summary)
    return summary


def _empty_aggregate() -> dict[str, Any]:
    return {
        "security_findings": [],
        "governance_findings": [],
        "severity_counts": Counter(),
        "category_counts": Counter(),
        "evidence_sources": set(),
        "user_context": {},
    }


def _add_security_findings(
    aggregates: dict[tuple[str, str], dict[str, Any]],
    findings: list[dict[str, Any]],
    user_profiles: dict[str, dict[str, str]],
) -> None:
    for finding in findings:
        user_id = finding.get("user_id")
        if user_id:
            _add_security_to_key(("user", str(user_id)), aggregates, finding, user_profiles)

        entity_type = str(finding.get("entity_type", "")).lower()
        entity_id = str(finding.get("entity_id", ""))
        if entity_type and entity_id and entity_type != "user":
            _add_security_to_key((entity_type, entity_id), aggregates, finding, user_profiles)


def _add_security_to_key(
    key: tuple[str, str],
    aggregates: dict[tuple[str, str], dict[str, Any]],
    finding: dict[str, Any],
    user_profiles: dict[str, dict[str, str]],
) -> None:
    aggregate = aggregates[key]
    aggregate["security_findings"].append(finding)
    aggregate["severity_counts"][str(finding.get("severity", "low")).lower()] += 1
    aggregate["evidence_sources"].add(str(finding.get("finding_id")))
    user_id = finding.get("user_id")
    if user_id and user_id in user_profiles:
        aggregate["user_context"].update(user_profiles[user_id])


def _add_governance_findings(
    aggregates: dict[tuple[str, str], dict[str, Any]],
    findings: list[dict[str, Any]],
    user_profiles: dict[str, dict[str, str]],
) -> None:
    for finding in findings:
        user_id = str(finding.get("user_id"))
        key = ("user", user_id)
        aggregate = aggregates[key]
        aggregate["governance_findings"].append(finding)
        aggregate["severity_counts"][str(finding.get("severity", "low")).lower()] += 1
        aggregate["category_counts"][str(finding.get("finding_category", "unknown"))] += 1
        aggregate["evidence_sources"].add(str(finding.get("governance_finding_id")))
        aggregate["user_context"].update(
            {
                "user_id": user_id,
                "user_principal_name": str(finding.get("user_principal_name", "")),
                "department": str(finding.get("department", "")),
                "role": str(finding.get("role", "")),
            }
        )
        if user_id in user_profiles:
            aggregate["user_context"].update(user_profiles[user_id])


def _score_aggregate(
    *,
    entity_type: str,
    entity_id: str,
    aggregate: dict[str, Any],
    scoring_timestamp: str,
    severity_weights: dict[str, int],
    category_weights: dict[str, int],
    score_cap: int,
    risk_bands: dict[str, dict[str, int]],
    privileged_roles: set[str],
) -> dict[str, Any]:
    severity_score, severity_factors = score_severities(
        dict(aggregate["severity_counts"]),
        severity_weights,
    )
    category_score, category_factors = score_governance_categories(
        dict(aggregate["category_counts"]),
        category_weights,
    )
    contributing_factors = severity_factors + category_factors
    raw_score = severity_score + category_score
    context = aggregate["user_context"]
    role = context.get("role", "")

    if role and is_privileged_role(role, privileged_roles):
        raw_score += 10
        contributing_factors.append("privileged role (+10)")
    if len(aggregate["category_counts"]) > 1:
        raw_score += 10
        contributing_factors.append("multiple finding categories (+10)")
    if aggregate["security_findings"] and aggregate["governance_findings"]:
        raw_score += 15
        contributing_factors.append("security and governance overlap (+15)")

    risk_score = cap_score(raw_score, score_cap)
    risk_band = assign_risk_band(risk_score, risk_bands)
    severity_counts = aggregate["severity_counts"]
    return build_risk_record(
        risk_id="",
        scoring_timestamp=scoring_timestamp,
        entity_type=entity_type,
        entity_id=entity_id,
        user_id=context.get("user_id") or (entity_id if entity_type == "user" else None),
        user_principal_name=context.get("user_principal_name", ""),
        department=context.get("department", ""),
        role=role,
        risk_score=risk_score,
        risk_band=risk_band,
        contributing_factors=contributing_factors,
        security_finding_count=len(aggregate["security_findings"]),
        governance_finding_count=len(aggregate["governance_findings"]),
        critical_count=int(severity_counts.get("critical", 0)),
        high_count=int(severity_counts.get("high", 0)),
        medium_count=int(severity_counts.get("medium", 0)),
        low_count=int(severity_counts.get("low", 0)),
        recommended_action=recommended_action_for_band(risk_band),
        evidence_sources=sorted(aggregate["evidence_sources"]),
    )


def _sort_and_number_records(risk_records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sorted_records = sorted(
        risk_records,
        key=lambda record: (
            -int(record["risk_score"]),
            -SEVERITY_ORDER.get(record["risk_band"], 0),
            record["entity_type"],
            record["entity_id"],
        ),
    )
    for index, record in enumerate(sorted_records, start=1):
        record["risk_id"] = f"RISK-{index:06d}"
    return sorted_records


def _load_user_profiles(input_dir: Path) -> dict[str, dict[str, str]]:
    identity_path = input_dir / "identity_events.csv"
    if not identity_path.exists():
        return {}
    dataframe = pd.read_csv(identity_path)
    if dataframe.empty:
        return {}
    profiles = {}
    for user_id, events in dataframe.sort_values("timestamp").groupby("user_id"):
        latest = events.iloc[-1]
        profiles[str(user_id)] = {
            "user_id": str(user_id),
            "user_principal_name": str(latest.get("user_principal_name", "")),
            "department": str(latest.get("department", "")),
            "role": str(latest.get("role", "")),
        }
    return profiles


def _data_quality_context(payload: dict[str, Any]) -> dict[str, Any]:
    if not payload:
        return {
            "available": False,
            "overall_data_quality_score": None,
            "dataset_statuses": {},
        }
    return {
        "available": True,
        "overall_data_quality_score": payload.get("overall_data_quality_score"),
        "dataset_statuses": {
            dataset.get("dataset_name"): dataset.get("status")
            for dataset in payload.get("datasets_validated", [])
        },
    }


def _settings_dict(
    settings: dict[str, Any],
    key: str,
    default: dict[str, int],
) -> dict[str, int]:
    values = settings.get(key, default)
    if not isinstance(values, dict):
        raise ValueError(f"risk_scoring.{key} must be a mapping")
    return {str(name): int(value) for name, value in values.items()}


def _load_json(path: str | Path) -> dict[str, Any]:
    json_path = Path(path)
    if not json_path.exists():
        raise FileNotFoundError(f"Required risk scoring input not found: {json_path}")
    return json.loads(json_path.read_text(encoding="utf-8"))


def _load_optional_json(path: str | Path) -> dict[str, Any]:
    json_path = Path(path)
    if not json_path.exists():
        return {}
    return json.loads(json_path.read_text(encoding="utf-8"))

