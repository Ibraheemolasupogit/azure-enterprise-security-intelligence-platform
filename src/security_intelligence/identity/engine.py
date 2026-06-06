"""Identity governance engine for processed telemetry datasets."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pandas as pd

from security_intelligence.config import load_yaml_config
from security_intelligence.identity.checks import (
    DEFAULT_PRIVILEGED_ROLES,
    DEFAULT_RISKY_RISK_HINTS,
    check_dormant_privileged_accounts,
    check_dormant_users,
    check_guest_user_exposure,
    check_mfa_disabled_or_missing,
    check_privileged_cloud_activity,
    check_risky_privilege_assignment,
    check_role_sprawl,
)
from security_intelligence.identity.models import SEVERITY_RANK
from security_intelligence.identity.summary import (
    summarize_findings,
    write_identity_governance_json,
    write_identity_governance_report,
    write_identity_review_csv,
)
from security_intelligence.paths import CONFIG_DIR, DATA_DIR, OUTPUT_DIR, REPORTS_DIR

REQUIRED_DATASETS = [
    "identity_events",
    "login_events",
    "application_events",
    "cloud_activity",
    "security_alerts",
]


class MissingIdentityInputError(FileNotFoundError):
    """Raised when processed telemetry files required for identity checks are missing."""

    def __init__(self, missing_files: list[Path]) -> None:
        self.missing_files = missing_files
        missing = ", ".join(str(path) for path in missing_files)
        super().__init__(f"Missing required identity governance input files: {missing}")


def run_identity_checks(
    input_dir: str | Path = DATA_DIR / "processed",
    output_path: str | Path = OUTPUT_DIR / "identity_governance_findings.json",
    review_path: str | Path = OUTPUT_DIR / "identity_review.csv",
    report_path: str | Path = REPORTS_DIR / "identity_governance_report.md",
    inactivity_days: int | None = None,
    config_path: str | Path = CONFIG_DIR / "platform.yaml",
) -> dict[str, Any]:
    """Run deterministic identity governance checks and write evidence outputs."""
    input_path = Path(input_dir)
    config = load_yaml_config(config_path)
    settings = config.get("identity_governance", {})
    resolved_inactivity_days = int(
        inactivity_days
        if inactivity_days is not None
        else settings.get("inactivity_days", 30)
    )
    role_sprawl_threshold = int(settings.get("role_sprawl_threshold", 2))
    privileged_roles = _settings_set(settings, "privileged_roles", DEFAULT_PRIVILEGED_ROLES)
    risky_risk_hints = _settings_set(settings, "risky_risk_hints", DEFAULT_RISKY_RISK_HINTS)

    datasets = _load_identity_datasets(input_path)
    check_timestamp = datetime.now(UTC).isoformat()
    reference_time = _latest_observed_timestamp(datasets)

    checks_executed = [
        "Dormant user",
        "Dormant privileged account",
        "MFA disabled or missing",
        "Guest user exposure",
        "Role sprawl",
        "Risky privilege assignment",
        "Privileged cloud activity",
    ]
    findings = []
    findings.extend(
        check_dormant_users(
            datasets["identity_events"],
            datasets["login_events"],
            check_timestamp=check_timestamp,
            reference_time=reference_time,
            inactivity_days=resolved_inactivity_days,
        )
    )
    findings.extend(
        check_dormant_privileged_accounts(
            datasets["identity_events"],
            datasets["login_events"],
            check_timestamp=check_timestamp,
            reference_time=reference_time,
            inactivity_days=resolved_inactivity_days,
            privileged_roles=privileged_roles,
        )
    )
    findings.extend(
        check_mfa_disabled_or_missing(
            datasets["identity_events"],
            check_timestamp=check_timestamp,
        )
    )
    findings.extend(
        check_guest_user_exposure(
            datasets["identity_events"],
            datasets["application_events"],
            datasets["cloud_activity"],
            check_timestamp=check_timestamp,
            privileged_roles=privileged_roles,
        )
    )
    findings.extend(
        check_role_sprawl(
            datasets["identity_events"],
            check_timestamp=check_timestamp,
            threshold=role_sprawl_threshold,
        )
    )
    findings.extend(
        check_risky_privilege_assignment(
            datasets["identity_events"],
            check_timestamp=check_timestamp,
            privileged_roles=privileged_roles,
            risky_risk_hints=risky_risk_hints,
        )
    )
    findings.extend(
        check_privileged_cloud_activity(
            datasets["identity_events"],
            datasets["cloud_activity"],
            check_timestamp=check_timestamp,
            privileged_roles=privileged_roles,
        )
    )

    findings = _assign_finding_ids(_sort_findings(_deduplicate_findings(findings)))
    findings_by_severity, findings_by_category = summarize_findings(findings)
    summary = {
        "governance_run_timestamp": check_timestamp,
        "input_dir": str(input_path),
        "total_findings": len(findings),
        "findings_by_severity": findings_by_severity,
        "findings_by_category": findings_by_category,
        "checks_executed": checks_executed,
        "datasets_used": REQUIRED_DATASETS,
        "findings": findings,
    }
    write_identity_governance_json(output_path, summary)
    write_identity_review_csv(review_path, findings)
    write_identity_governance_report(report_path, summary)
    return summary


def _load_identity_datasets(input_dir: Path) -> dict[str, pd.DataFrame]:
    missing_files = [
        input_dir / f"{dataset_name}.csv"
        for dataset_name in REQUIRED_DATASETS
        if not (input_dir / f"{dataset_name}.csv").exists()
    ]
    if missing_files:
        raise MissingIdentityInputError(missing_files)
    return {
        dataset_name: pd.read_csv(input_dir / f"{dataset_name}.csv")
        for dataset_name in REQUIRED_DATASETS
    }


def _latest_observed_timestamp(datasets: dict[str, pd.DataFrame]) -> pd.Timestamp:
    timestamps = []
    for dataframe in datasets.values():
        if "timestamp" in dataframe.columns and not dataframe.empty:
            parsed = pd.to_datetime(dataframe["timestamp"], errors="coerce").dropna()
            if not parsed.empty:
                timestamps.append(parsed.max())
    if not timestamps:
        return pd.Timestamp(datetime.now(UTC))
    return max(timestamps)


def _deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    deduped = []
    for finding in findings:
        evidence_key = tuple(
            sorted((str(key), str(value)) for key, value in finding["evidence"].items())
        )
        key = (finding["check_id"], finding["user_id"], finding["finding_category"], evidence_key)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped


def _sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        findings,
        key=lambda finding: (
            -SEVERITY_RANK.get(finding["severity"], 0),
            finding["user_principal_name"],
            finding["check_id"],
        ),
    )


def _assign_finding_ids(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for index, finding in enumerate(findings, start=1):
        finding["governance_finding_id"] = f"IDG-FIND-{index:06d}"
    return findings


def _settings_set(settings: dict[str, Any], key: str, default: set[str]) -> set[str]:
    values = settings.get(key, sorted(default))
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise ValueError(f"identity_governance.{key} must be a list of strings")
    return {value.lower() for value in values}
