"""Identity governance output writers."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import pandas as pd

from security_intelligence.identity.models import SEVERITY_RANK


def write_identity_governance_json(output_path: str | Path, summary: dict[str, Any]) -> None:
    """Write machine-readable identity governance findings."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_identity_review_csv(review_path: str | Path, findings: list[dict[str, Any]]) -> None:
    """Write a flattened identity review CSV grouped by user."""
    path = Path(review_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = build_identity_review_rows(findings)
    pd.DataFrame(rows).to_csv(path, index=False)


def write_identity_governance_report(report_path: str | Path, summary: dict[str, Any]) -> None:
    """Write a human-readable identity governance report."""
    path = Path(report_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    review_rows = build_identity_review_rows(summary["findings"])
    lines = [
        "# Identity Governance Report",
        "",
        "## Executive Summary",
        "",
        (
            f"Identity governance checks identified {summary['total_findings']} findings "
            f"across {len(summary['datasets_used'])} processed synthetic telemetry datasets."
        ),
        "",
        "These checks are local-first and based on synthetic identity telemetry only. "
        "They do not connect to Azure, Microsoft Graph, or real identity data.",
        "",
        "## Findings By Severity",
        "",
    ]
    for severity, count in summary["findings_by_severity"].items():
        lines.append(f"- {severity}: {count}")

    lines.extend(["", "## Findings By Category", ""])
    for category, count in summary["findings_by_category"].items():
        lines.append(f"- {category}: {count}")

    lines.extend(
        [
            "",
            "## Identity Review Table",
            "",
            "| User | Department | Role | Highest Severity | Categories | Findings |",
            "| --- | --- | --- | --- | --- | ---: |",
        ]
    )
    for row in review_rows[:20]:
        lines.append(
            "| {user_principal_name} | {department} | {role} | {highest_severity} | "
            "{finding_categories} | {finding_count} |".format(**row)
        )

    lines.extend(["", "## Highest-Risk Users", ""])
    for row in review_rows[:10]:
        lines.append(
            f"- {row['user_principal_name']}: {row['highest_severity']} "
            f"({row['finding_count']} findings)"
        )

    lines.extend(
        [
            "",
            "## Recommended Next Actions",
            "",
            "- Review high and critical identity governance findings first.",
            "- Validate privileged assignments against least-privilege and access review policy.",
            "- Confirm MFA posture for users with disabled or missing MFA signals.",
            "- Review guest identities for ownership, expiration, and sensitive access.",
            "- Preserve JSON and CSV outputs as governance evidence for later reporting.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def build_identity_review_rows(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build flattened identity review rows grouped by user."""
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        grouped[finding["user_id"]].append(finding)

    rows = []
    for user_id, user_findings in grouped.items():
        highest = max(
            (finding["severity"] for finding in user_findings),
            key=lambda severity: SEVERITY_RANK.get(severity, 0),
        )
        first = user_findings[0]
        categories = sorted({finding["finding_category"] for finding in user_findings})
        action = _highest_severity_finding(user_findings)["recommended_action"]
        rows.append(
            {
                "user_id": user_id,
                "user_principal_name": first["user_principal_name"],
                "department": first["department"],
                "role": first["role"],
                "highest_severity": highest,
                "finding_categories": "; ".join(categories),
                "finding_count": len(user_findings),
                "recommended_action": action,
            }
        )

    return sorted(
        rows,
        key=lambda row: (
            -SEVERITY_RANK.get(row["highest_severity"], 0),
            -int(row["finding_count"]),
            row["user_principal_name"],
        ),
    )


def summarize_findings(findings: list[dict[str, Any]]) -> tuple[dict[str, int], dict[str, int]]:
    """Summarize findings by severity and category."""
    severity_counts = Counter(finding["severity"] for finding in findings)
    category_counts = Counter(finding["finding_category"] for finding in findings)
    return dict(severity_counts), dict(category_counts)


def _highest_severity_finding(findings: list[dict[str, Any]]) -> dict[str, Any]:
    return max(findings, key=lambda finding: SEVERITY_RANK.get(finding["severity"], 0))

