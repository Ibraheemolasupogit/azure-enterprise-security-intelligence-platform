"""Monitoring output writers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def write_operational_health_summary(output_path: str | Path, summary: dict[str, Any]) -> None:
    """Write machine-readable operational health summary."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_evidence_manifest(output_path: str | Path, manifest: dict[str, Any]) -> None:
    """Write evidence manifest JSON."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_operational_evidence_report(
    report_path: str | Path,
    health_summary: dict[str, Any],
    evidence_manifest: dict[str, Any],
) -> None:
    """Write human-readable operational evidence report."""
    path = Path(report_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    key_metrics = health_summary["key_metrics"]
    stage_results = health_summary["stage_results"]
    artifact_count = len(evidence_manifest["artifacts"])
    existing_artifacts = sum(1 for artifact in evidence_manifest["artifacts"] if artifact["exists"])

    lines = [
        "# Operational Evidence Report",
        "",
        "## Executive Summary",
        "",
        (
            f"Monitoring checked {health_summary['stages_checked']} pipeline stages and "
            f"{artifact_count} evidence artifacts. Overall platform health is "
            f"{health_summary['overall_status']}."
        ),
        "",
        "Monitoring is local-first and simulates Azure Monitor and Microsoft Sentinel-style "
        "operational evidence. It does not connect to Azure or use real data.",
        "",
        "## Overall Platform Health Status",
        "",
        health_summary["overall_status"],
        "",
        "## Pipeline Stage Health",
        "",
        "| Stage | Status | Artifact | Records | Warnings | Failures |",
        "| --- | --- | --- | ---: | ---: | ---: |",
    ]
    for result in stage_results:
        lines.append(
            "| {pipeline_stage} | {status} | {input_artifact} | {record_count} | "
            "{warnings} | {failures} |".format(
                pipeline_stage=result["pipeline_stage"],
                status=result["status"],
                input_artifact=result["input_artifact"],
                record_count=result["record_count"] if result["record_count"] is not None else "",
                warnings=len(result["warnings"]),
                failures=len(result["failures"]),
            )
        )

    lines.extend(
        [
            "",
            "## Key Operational Metrics",
            "",
        ]
    )
    for name, value in key_metrics.items():
        lines.append(f"- {name}: {value}")

    lines.extend(
        [
            "",
            "## Security Posture Highlights",
            "",
            f"- Total security findings: {key_metrics.get('security_findings_total', 0)}",
            f"- Critical security findings: {key_metrics.get('critical_security_findings', 0)}",
            "",
            "## Identity Governance Highlights",
            "",
            (
                "- Total identity governance findings: "
                f"{key_metrics.get('identity_findings_total', 0)}"
            ),
            (
                "- Critical/high identity findings: "
                f"{key_metrics.get('critical_high_identity_findings', 0)}"
            ),
            "",
            "## Risk Scoring Highlights",
            "",
            f"- Total entities scored: {key_metrics.get('entities_scored', 0)}",
            f"- Critical risk entities: {key_metrics.get('critical_risk_entities', 0)}",
            "",
            "## Evidence Manifest Summary",
            "",
            f"- Evidence artifacts listed: {artifact_count}",
            f"- Evidence artifacts available: {existing_artifacts}",
            "",
            "## Recommended Next Actions",
            "",
        ]
    )
    for action in health_summary["recommended_next_actions"]:
        lines.append(f"- {action}")
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")
