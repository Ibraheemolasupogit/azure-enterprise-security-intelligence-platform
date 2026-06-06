"""Security finding output writers."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any


def write_findings_json(output_path: str | Path, summary: dict[str, Any]) -> None:
    """Write machine-readable detection findings."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_findings_report(report_path: str | Path, summary: dict[str, Any]) -> None:
    """Write a human-readable Markdown detection report."""
    path = Path(report_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    findings = summary["findings"]
    mitre_counter = Counter(
        f"{finding['mitre_tactic']} / {finding['mitre_technique']}" for finding in findings
    )
    lines = [
        "# Security Findings Report",
        "",
        "## Executive Summary",
        "",
        (
            f"Deterministic detection rules identified {summary['total_findings']} findings "
            f"across {len(summary['datasets_used'])} processed telemetry datasets."
        ),
        "",
        "These detections are deterministic and based on synthetic local telemetry only. "
        "They do not connect to Azure, use real data, or require credentials.",
        "",
        "## Total Findings",
        "",
        str(summary["total_findings"]),
        "",
        "## Findings By Severity",
        "",
    ]

    for severity, count in summary["findings_by_severity"].items():
        lines.append(f"- {severity}: {count}")

    lines.extend(["", "## Findings By Rule", ""])
    for rule_name, count in summary["findings_by_rule"].items():
        lines.append(f"- {rule_name}: {count}")

    lines.extend(
        [
            "",
            "## Top Findings",
            "",
            "| Finding ID | Severity | Rule | Entity | Source | Description |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    for finding in findings[:10]:
        lines.append(
            "| {finding_id} | {severity} | {rule_name} | {entity_id} | "
            "{source_dataset} | {description} |".format(**finding)
        )

    lines.extend(["", "## MITRE ATT&CK Coverage", ""])
    if mitre_counter:
        for mapping, count in sorted(mitre_counter.items()):
            lines.append(f"- {mapping}: {count}")
    else:
        lines.append("No MITRE mappings were produced.")

    lines.extend(
        [
            "",
            "## Recommended Next Actions",
            "",
            "- Review high and critical findings before downstream scoring.",
            "- Compare findings with validation evidence before building governance checks.",
            "- Preserve JSON output for future reporting and dashboard milestones.",
            "- Tune thresholds in `configs/detection_rules.yaml` as synthetic scenarios evolve.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")

