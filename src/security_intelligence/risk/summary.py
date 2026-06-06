"""Risk scoring output writers."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import pandas as pd

CSV_COLUMNS = [
    "risk_id",
    "entity_type",
    "entity_id",
    "user_id",
    "user_principal_name",
    "department",
    "role",
    "risk_score",
    "risk_band",
    "security_finding_count",
    "governance_finding_count",
    "critical_count",
    "high_count",
    "medium_count",
    "low_count",
    "recommended_action",
]


def write_risk_json(output_path: str | Path, summary: dict[str, Any]) -> None:
    """Write machine-readable risk score output."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_risk_csv(csv_path: str | Path, risk_scores: list[dict[str, Any]]) -> None:
    """Write flattened risk score CSV output."""
    path = Path(csv_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = [{column: record.get(column) for column in CSV_COLUMNS} for record in risk_scores]
    pd.DataFrame(rows, columns=CSV_COLUMNS).to_csv(path, index=False)


def write_risk_report(report_path: str | Path, summary: dict[str, Any]) -> None:
    """Write a human-readable Markdown risk scoring report."""
    path = Path(report_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    risk_scores = summary["risk_scores"]
    factor_counter = Counter(
        factor for record in risk_scores for factor in record["contributing_factors"]
    )
    lines = [
        "# Risk Scoring Report",
        "",
        "## Executive Summary",
        "",
        (
            f"Deterministic risk scoring produced {summary['total_entities_scored']} "
            "entity risk records from local synthetic security and governance evidence."
        ),
        "",
        "Scoring is deterministic and based on synthetic local telemetry only. "
        "It does not use real data, Azure services, ML models, or GenAI workflows.",
        "",
        "## Total Entities Scored",
        "",
        str(summary["total_entities_scored"]),
        "",
        "## Risk Band Distribution",
        "",
    ]
    for band, count in summary["risk_band_counts"].items():
        lines.append(f"- {band}: {count}")

    lines.extend(
        [
            "",
            "## Top 10 Highest-Risk Entities",
            "",
            "| Risk ID | Entity | Type | Score | Band | Security | Governance | Action |",
            "| --- | --- | --- | ---: | --- | ---: | ---: | --- |",
        ]
    )
    for record in risk_scores[:10]:
        lines.append(
            "| {risk_id} | {entity_id} | {entity_type} | {risk_score} | {risk_band} | "
            "{security_finding_count} | {governance_finding_count} | "
            "{recommended_action} |".format(**record)
        )

    lines.extend(["", "## Key Contributing Factors", ""])
    for factor, count in factor_counter.most_common(10):
        lines.append(f"- {factor}: {count}")

    lines.extend(
        [
            "",
            "## Scoring Method Summary",
            "",
            "Scores combine severity-weighted security and governance findings, "
            "governance category weights, privileged-role modifiers, multiple-category "
            "modifiers, and overlap between security and governance evidence. Scores "
            "are capped at the configured maximum and assigned to low, medium, high, "
            "or critical bands.",
            "",
            "## Recommended Next Actions",
            "",
            "- Prioritize critical and high risk entities for SOC and governance review.",
            "- Use contributing factors to explain why an entity was prioritized.",
            "- Preserve JSON and CSV outputs for future dashboard and reporting milestones.",
            "- Revisit deterministic weights as additional telemetry scenarios are added.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")
