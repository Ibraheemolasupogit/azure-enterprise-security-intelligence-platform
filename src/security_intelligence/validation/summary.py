"""Data quality summary and report writers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def write_data_quality_summary(summary_path: str | Path, summary: dict[str, Any]) -> None:
    """Write the machine-readable data quality summary."""
    path = Path(summary_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_data_quality_report(report_path: str | Path, summary: dict[str, Any]) -> None:
    """Write a human-readable Markdown data quality report."""
    path = Path(report_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    datasets = summary["datasets_validated"]
    warning_lines = _finding_lines(datasets, "warnings")
    failure_lines = _finding_lines(datasets, "failures")

    lines = [
        "# Data Quality Report",
        "",
        "## Executive Summary",
        "",
        (
            f"Validation completed for {len(datasets)} processed synthetic telemetry datasets. "
            f"The overall data quality score is {summary['overall_data_quality_score']:.1f}/100."
        ),
        "",
        "This validation is local-first and uses synthetic data only. "
        "It does not connect to Azure, "
        "use real user data, or require credentials.",
        "",
        "## Dataset Validation Table",
        "",
        "| Dataset | Status | Records | Columns | Score |",
        "| --- | --- | ---: | ---: | ---: |",
    ]

    for dataset in datasets:
        lines.append(
            "| {dataset_name} | {status} | {record_count} | {column_count} | "
            "{data_quality_score:.1f} |".format(**dataset)
        )

    lines.extend(["", "## Warnings And Failures", ""])
    if not warning_lines and not failure_lines:
        lines.append("No warnings or failures were identified.")
    else:
        if failure_lines:
            lines.extend(["### Failures", "", *failure_lines])
        if warning_lines:
            lines.extend(["", "### Warnings", "", *warning_lines])

    lines.extend(
        [
            "",
            "## Overall Data Quality Score",
            "",
            f"{summary['overall_data_quality_score']:.1f}/100",
            "",
            "## Recommended Next Actions",
            "",
            "- Review failed checks before using datasets for downstream analytics.",
            "- Investigate warning-level schema or value issues.",
            "- Preserve the JSON summary as machine-readable evidence for later milestones.",
            "- Use this report as local validation evidence for detection and reporting workflows.",
            "",
        ]
    )

    path.write_text("\n".join(lines), encoding="utf-8")


def _finding_lines(datasets: list[dict[str, Any]], key: str) -> list[str]:
    lines = []
    for dataset in datasets:
        for check in dataset[key]:
            lines.append(f"- **{dataset['dataset_name']}**: {check['name']} - {check['message']}")
    return lines
