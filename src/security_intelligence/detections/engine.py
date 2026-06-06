"""Detection engine for processed telemetry datasets."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pandas as pd

from security_intelligence.config import load_yaml_config
from security_intelligence.detections.models import SEVERITY_RANK
from security_intelligence.detections.rules import (
    detect_bulk_application_export,
    detect_impossible_travel,
    detect_malware,
    detect_privileged_role_activation,
    detect_repeated_failed_login,
    detect_suspicious_cloud_change,
    detect_suspicious_powershell,
)
from security_intelligence.detections.summary import (
    write_findings_json,
    write_findings_report,
)
from security_intelligence.ingestion.pipeline import discover_expected_datasets
from security_intelligence.paths import CONFIG_DIR, DATA_DIR, OUTPUT_DIR, REPORTS_DIR

RuleFunction = Callable[[dict[str, pd.DataFrame], dict[str, Any], str], list[dict[str, Any]]]


class MissingDetectionInputError(FileNotFoundError):
    """Raised when processed telemetry files required for detections are missing."""

    def __init__(self, missing_files: list[Path]) -> None:
        self.missing_files = missing_files
        missing = ", ".join(str(path) for path in missing_files)
        super().__init__(f"Missing required detection input files: {missing}")


def run_detections(
    input_dir: str | Path = DATA_DIR / "processed",
    output_path: str | Path = OUTPUT_DIR / "security_findings.json",
    report_path: str | Path = REPORTS_DIR / "security_findings_report.md",
    config_path: str | Path = CONFIG_DIR / "detection_rules.yaml",
    platform_config_path: str | Path = CONFIG_DIR / "platform.yaml",
) -> dict[str, Any]:
    """Run deterministic detection rules against processed telemetry CSV files."""
    input_path = Path(input_dir)
    detection_timestamp = datetime.now(UTC).isoformat()
    datasets = _load_processed_datasets(input_path, platform_config_path)
    enabled_rules = _load_enabled_rules(config_path)

    findings: list[dict[str, Any]] = []
    for rule in enabled_rules:
        rule_function = RULE_FUNCTIONS.get(rule["rule_id"])
        if rule_function is None:
            continue
        findings.extend(rule_function(datasets, rule, detection_timestamp))

    findings = _assign_finding_ids(_sort_findings(_deduplicate_findings(findings)))
    summary = {
        "detection_run_timestamp": detection_timestamp,
        "input_dir": str(input_path),
        "total_findings": len(findings),
        "findings_by_severity": dict(Counter(finding["severity"] for finding in findings)),
        "findings_by_rule": dict(Counter(finding["rule_name"] for finding in findings)),
        "findings": findings,
        "rules_executed": [
            {
                "rule_id": rule["rule_id"],
                "rule_name": rule["rule_name"],
                "enabled": rule.get("enabled", True),
            }
            for rule in enabled_rules
        ],
        "datasets_used": sorted(datasets),
    }
    write_findings_json(output_path, summary)
    write_findings_report(report_path, summary)
    return summary


def _load_processed_datasets(
    input_dir: Path,
    platform_config_path: str | Path,
) -> dict[str, pd.DataFrame]:
    expected_csv_files = [
        f"{Path(filename).stem}.csv"
        for filename in discover_expected_datasets(platform_config_path)
    ]
    missing_files = [
        input_dir / filename
        for filename in expected_csv_files
        if not (input_dir / filename).exists()
    ]
    if missing_files:
        raise MissingDetectionInputError(missing_files)

    return {
        Path(filename).stem: pd.read_csv(input_dir / filename)
        for filename in expected_csv_files
    }


def _load_enabled_rules(config_path: str | Path) -> list[dict[str, Any]]:
    config = load_yaml_config(config_path)
    rules = config.get("detection_rules", [])
    if not isinstance(rules, list):
        raise ValueError("detection_rules must be a list")

    normalized_rules = []
    for rule in rules:
        if not isinstance(rule, dict):
            raise ValueError("Each detection rule must be a mapping")
        normalized = {
            "rule_id": rule.get("rule_id") or rule.get("id"),
            "rule_name": rule.get("rule_name") or rule.get("name"),
            "description": rule.get("description", ""),
            "severity": str(rule.get("severity", "medium")).lower(),
            "enabled": bool(rule.get("enabled", True)),
            "mitre_tactic": rule.get("mitre_tactic", "Unknown"),
            "mitre_technique": rule.get("mitre_technique", "Unknown"),
            **{key: value for key, value in rule.items() if key not in {"id", "name"}},
        }
        if not normalized["rule_id"] or not normalized["rule_name"]:
            raise ValueError("Each detection rule requires rule_id and rule_name")
        if normalized["enabled"]:
            normalized_rules.append(normalized)
    return normalized_rules


def _wrap_impossible(
    datasets: dict[str, pd.DataFrame], rule: dict[str, Any], timestamp: str
) -> list[dict[str, Any]]:
    return detect_impossible_travel(datasets["login_events"], rule, timestamp)


def _wrap_failed_login(
    datasets: dict[str, pd.DataFrame], rule: dict[str, Any], timestamp: str
) -> list[dict[str, Any]]:
    return detect_repeated_failed_login(datasets["login_events"], rule, timestamp)


def _wrap_privileged(
    datasets: dict[str, pd.DataFrame], rule: dict[str, Any], timestamp: str
) -> list[dict[str, Any]]:
    return detect_privileged_role_activation(datasets["identity_events"], rule, timestamp)


def _wrap_powershell(
    datasets: dict[str, pd.DataFrame], rule: dict[str, Any], timestamp: str
) -> list[dict[str, Any]]:
    return detect_suspicious_powershell(datasets["endpoint_events"], rule, timestamp)


def _wrap_malware(
    datasets: dict[str, pd.DataFrame], rule: dict[str, Any], timestamp: str
) -> list[dict[str, Any]]:
    return detect_malware(datasets["endpoint_events"], datasets["security_alerts"], rule, timestamp)


def _wrap_cloud(
    datasets: dict[str, pd.DataFrame], rule: dict[str, Any], timestamp: str
) -> list[dict[str, Any]]:
    return detect_suspicious_cloud_change(datasets["cloud_activity"], rule, timestamp)


def _wrap_bulk_export(
    datasets: dict[str, pd.DataFrame], rule: dict[str, Any], timestamp: str
) -> list[dict[str, Any]]:
    return detect_bulk_application_export(datasets["application_events"], rule, timestamp)


RULE_FUNCTIONS: dict[str, RuleFunction] = {
    "DET-001": _wrap_impossible,
    "DET-002": _wrap_failed_login,
    "DET-003": _wrap_privileged,
    "DET-004": _wrap_powershell,
    "DET-005": _wrap_malware,
    "DET-006": _wrap_cloud,
    "DET-007": _wrap_bulk_export,
}


def _deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    deduped = []
    for finding in findings:
        key = (finding["rule_id"], finding["source_dataset"], finding["event_id"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped


def _sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        findings,
        key=lambda finding: (
            -SEVERITY_RANK.get(str(finding["severity"]).lower(), 0),
            finding["detection_timestamp"],
            finding["rule_id"],
            finding["event_id"],
        ),
    )


def _assign_finding_ids(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for index, finding in enumerate(findings, start=1):
        finding["finding_id"] = f"FIND-{index:06d}"
    return findings
