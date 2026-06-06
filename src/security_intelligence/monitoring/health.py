"""Operational health checks for local platform artifacts."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def build_stage_result(
    *,
    monitoring_timestamp: str,
    pipeline_stage: str,
    input_artifact: str,
    artifact_exists: bool,
    status: str,
    record_count: int | None,
    key_metrics: dict[str, Any],
    warnings: list[str],
    failures: list[str],
    recommended_action: str,
) -> dict[str, Any]:
    """Build a structured pipeline health result."""
    return {
        "monitoring_timestamp": monitoring_timestamp,
        "pipeline_stage": pipeline_stage,
        "input_artifact": input_artifact,
        "artifact_exists": artifact_exists,
        "status": status,
        "record_count": record_count,
        "key_metrics": key_metrics,
        "warnings": warnings,
        "failures": failures,
        "recommended_action": recommended_action,
    }


def load_json_if_exists(path: str | Path) -> dict[str, Any]:
    """Load JSON from a path, returning an empty mapping if missing."""
    json_path = Path(path)
    if not json_path.exists():
        return {}
    return json.loads(json_path.read_text(encoding="utf-8"))


def artifact_freshness_warning(path: Path, freshness_hours: int) -> str | None:
    """Return a warning if an artifact is older than the freshness threshold."""
    if not path.exists():
        return None
    modified = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
    age_hours = (datetime.now(UTC) - modified).total_seconds() / 3600
    if age_hours > freshness_hours:
        return f"Artifact is stale: {age_hours:.1f} hours old"
    return None


def status_from_findings(warnings: list[str], failures: list[str]) -> str:
    """Derive a stage status from warnings and failures."""
    if failures:
        return "failed"
    if warnings:
        return "warning"
    return "passed"


def check_artifact_stage(
    *,
    stage: str,
    path: Path,
    monitoring_timestamp: str,
    freshness_hours: int,
    record_count: int | None,
    key_metrics: dict[str, Any],
    warnings: list[str] | None = None,
    failures: list[str] | None = None,
    recommended_action: str = "No action required.",
) -> dict[str, Any]:
    """Build a stage result with artifact existence and freshness checks."""
    stage_warnings = list(warnings or [])
    stage_failures = list(failures or [])
    exists = path.exists()
    if not exists:
        stage_failures.append(f"Missing critical output: {path}")
        recommended_action = "Regenerate the missing pipeline artifact."
    else:
        freshness_warning = artifact_freshness_warning(path, freshness_hours)
        if freshness_warning:
            stage_warnings.append(freshness_warning)

    return build_stage_result(
        monitoring_timestamp=monitoring_timestamp,
        pipeline_stage=stage,
        input_artifact=str(path),
        artifact_exists=exists,
        status=status_from_findings(stage_warnings, stage_failures),
        record_count=record_count,
        key_metrics=key_metrics,
        warnings=stage_warnings,
        failures=stage_failures,
        recommended_action=recommended_action,
    )

