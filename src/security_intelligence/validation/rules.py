"""Reusable validation rules for processed telemetry datasets."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd

PROCESSED_REQUIRED_COLUMNS = {
    "identity_events": [
        "event_id",
        "timestamp",
        "user_id",
        "user_principal_name",
        "department",
        "role",
        "event_type",
        "source_system",
        "risk_hint",
        "location",
        "metadata",
        "ingestion_timestamp",
        "source_dataset",
        "source_file",
    ],
    "login_events": [
        "event_id",
        "timestamp",
        "user_id",
        "user_principal_name",
        "ip_address",
        "country",
        "city",
        "device_id",
        "auth_method",
        "login_status",
        "failure_reason",
        "risk_hint",
        "metadata",
        "ingestion_timestamp",
        "source_dataset",
        "source_file",
    ],
    "endpoint_events": [
        "event_id",
        "timestamp",
        "device_id",
        "hostname",
        "user_id",
        "process_name",
        "event_type",
        "severity",
        "risk_hint",
        "metadata",
        "ingestion_timestamp",
        "source_dataset",
        "source_file",
    ],
    "application_events": [
        "event_id",
        "timestamp",
        "application_name",
        "user_id",
        "user_principal_name",
        "event_type",
        "resource",
        "action",
        "severity",
        "risk_hint",
        "metadata",
        "ingestion_timestamp",
        "source_dataset",
        "source_file",
    ],
    "security_alerts": [
        "alert_id",
        "timestamp",
        "alert_name",
        "severity",
        "entity_type",
        "entity_id",
        "user_id",
        "description",
        "mitre_tactic",
        "mitre_technique",
        "status",
        "risk_hint",
        "metadata",
        "ingestion_timestamp",
        "source_dataset",
        "source_file",
    ],
    "cloud_activity": [
        "event_id",
        "timestamp",
        "subscription_id",
        "resource_group",
        "resource_type",
        "resource_name",
        "operation_name",
        "caller",
        "result",
        "severity",
        "risk_hint",
        "metadata",
        "ingestion_timestamp",
        "source_dataset",
        "source_file",
    ],
}

ID_COLUMNS = {
    "identity_events": "event_id",
    "login_events": "event_id",
    "endpoint_events": "event_id",
    "application_events": "event_id",
    "security_alerts": "alert_id",
    "cloud_activity": "event_id",
}

DEFAULT_ALLOWED_SEVERITIES = {"low", "medium", "high", "critical"}
DEFAULT_ALLOWED_RISK_HINTS = {"normal", "low", "medium", "high", "critical"}


def make_check(
    name: str,
    status: str,
    message: str,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a standard validation check result."""
    return {
        "name": name,
        "status": status,
        "message": message,
        "details": details or {},
    }


def check_file_exists(path: Path) -> dict[str, Any]:
    """Validate that a processed dataset file exists."""
    if path.exists():
        return make_check("file_exists", "passed", f"File exists: {path}")
    return make_check("file_exists", "failed", f"Missing processed file: {path}")


def check_file_not_empty(path: Path) -> dict[str, Any]:
    """Validate that a processed dataset file is not empty."""
    if path.exists() and path.stat().st_size > 0:
        return make_check("file_not_empty", "passed", "File is not empty")
    return make_check("file_not_empty", "failed", f"Processed file is empty: {path}")


def check_required_columns(dataframe: pd.DataFrame, required_columns: list[str]) -> dict[str, Any]:
    """Validate that all dataset-specific required columns exist."""
    missing_columns = [column for column in required_columns if column not in dataframe.columns]
    if not missing_columns:
        return make_check("required_columns", "passed", "All required columns are present")
    return make_check(
        "required_columns",
        "failed",
        "Missing required columns",
        {"missing_columns": missing_columns},
    )


def check_required_id_values(dataframe: pd.DataFrame, id_column: str) -> dict[str, Any]:
    """Validate that the required identifier column has no missing values."""
    if id_column not in dataframe.columns:
        return make_check("required_id_values", "failed", f"Missing ID column: {id_column}")
    missing_count = int(dataframe[id_column].isna().sum())
    blank_count = int((dataframe[id_column].astype(str).str.strip() == "").sum())
    total_missing = missing_count + blank_count
    if total_missing == 0:
        return make_check("required_id_values", "passed", f"{id_column} has no missing values")
    return make_check(
        "required_id_values",
        "failed",
        f"{id_column} contains missing values",
        {"missing_count": total_missing},
    )


def check_duplicate_ids(dataframe: pd.DataFrame, id_column: str) -> dict[str, Any]:
    """Validate that the required identifier column has no duplicates."""
    if id_column not in dataframe.columns:
        return make_check("duplicate_ids", "failed", f"Missing ID column: {id_column}")
    duplicate_count = int(dataframe[id_column].duplicated().sum())
    if duplicate_count == 0:
        return make_check("duplicate_ids", "passed", f"{id_column} has no duplicate values")
    return make_check(
        "duplicate_ids",
        "failed",
        f"{id_column} contains duplicate values",
        {"duplicate_count": duplicate_count},
    )


def check_timestamp_column(dataframe: pd.DataFrame) -> dict[str, Any]:
    """Validate that the event timestamp column exists."""
    if "timestamp" in dataframe.columns:
        return make_check("timestamp_column", "passed", "timestamp column exists")
    return make_check("timestamp_column", "failed", "timestamp column is missing")


def check_timestamp_parseable(dataframe: pd.DataFrame) -> dict[str, Any]:
    """Validate that event timestamp values can be parsed."""
    if "timestamp" not in dataframe.columns:
        return make_check("timestamp_parseable", "failed", "timestamp column is missing")
    parsed = pd.to_datetime(dataframe["timestamp"], errors="coerce")
    invalid_count = int(parsed.isna().sum())
    if invalid_count == 0:
        return make_check("timestamp_parseable", "passed", "All timestamp values are parseable")
    return make_check(
        "timestamp_parseable",
        "failed",
        "Unparseable timestamp values found",
        {"invalid_count": invalid_count},
    )


def check_allowed_values(
    dataframe: pd.DataFrame,
    column: str,
    allowed_values: set[str],
    rule_name: str,
) -> dict[str, Any]:
    """Validate that a column only contains allowed values when present."""
    if column not in dataframe.columns:
        return make_check(rule_name, "passed", f"{column} column is not applicable")

    values = set(dataframe[column].dropna().astype(str).str.lower().unique())
    invalid_values = sorted(values - allowed_values)
    if not invalid_values:
        return make_check(rule_name, "passed", f"{column} values are allowed")
    return make_check(
        rule_name,
        "warning",
        f"{column} contains values outside the allowed set",
        {"invalid_values": invalid_values, "allowed_values": sorted(allowed_values)},
    )


def check_column_exists(dataframe: pd.DataFrame, column: str, rule_name: str) -> dict[str, Any]:
    """Validate that a metadata column exists."""
    if column in dataframe.columns:
        return make_check(rule_name, "passed", f"{column} column exists")
    return make_check(rule_name, "failed", f"{column} column is missing")


def check_source_dataset_value(dataframe: pd.DataFrame, dataset_name: str) -> dict[str, Any]:
    """Warn when source_dataset values do not match the expected dataset name."""
    if "source_dataset" not in dataframe.columns:
        return make_check("source_dataset_value", "failed", "source_dataset column is missing")

    values = set(dataframe["source_dataset"].dropna().astype(str).unique())
    if values == {dataset_name}:
        return make_check("source_dataset_value", "passed", "source_dataset values match")
    return make_check(
        "source_dataset_value",
        "warning",
        "source_dataset contains unexpected values",
        {"expected": dataset_name, "observed": sorted(values)},
    )
