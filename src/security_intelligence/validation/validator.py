"""Validation pipeline for processed telemetry CSV files."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pandas as pd
from pandas.errors import EmptyDataError

from security_intelligence.config import load_yaml_config
from security_intelligence.ingestion.pipeline import discover_expected_datasets
from security_intelligence.paths import CONFIG_DIR, DATA_DIR, OUTPUT_DIR, REPORTS_DIR
from security_intelligence.validation.rules import (
    DEFAULT_ALLOWED_RISK_HINTS,
    DEFAULT_ALLOWED_SEVERITIES,
    ID_COLUMNS,
    PROCESSED_REQUIRED_COLUMNS,
    check_allowed_values,
    check_column_exists,
    check_duplicate_ids,
    check_file_exists,
    check_file_not_empty,
    check_required_columns,
    check_required_id_values,
    check_source_dataset_value,
    check_timestamp_column,
    check_timestamp_parseable,
    make_check,
)
from security_intelligence.validation.summary import (
    write_data_quality_report,
    write_data_quality_summary,
)


class MissingProcessedDatasetsError(FileNotFoundError):
    """Raised when required processed telemetry datasets are missing."""

    def __init__(self, missing_files: list[Path]) -> None:
        self.missing_files = missing_files
        missing = ", ".join(str(path) for path in missing_files)
        super().__init__(f"Missing required processed telemetry files: {missing}")


def validate_telemetry(
    input_dir: str | Path = DATA_DIR / "processed",
    summary_path: str | Path = OUTPUT_DIR / "data_quality_summary.json",
    report_path: str | Path = REPORTS_DIR / "data_quality_report.md",
    config_path: str | Path = CONFIG_DIR / "platform.yaml",
) -> dict[str, Any]:
    """Validate processed telemetry CSV files and write evidence outputs."""
    input_path = Path(input_dir)
    config = load_yaml_config(config_path)
    expected_csv_files = [
        _jsonl_to_csv(filename) for filename in discover_expected_datasets(config_path)
    ]
    missing_files = [
        input_path / filename
        for filename in expected_csv_files
        if not (input_path / filename).exists()
    ]

    if missing_files:
        raise MissingProcessedDatasetsError(missing_files)

    allowed_severities = _allowed_values(
        config,
        "allowed_severities",
        DEFAULT_ALLOWED_SEVERITIES,
    )
    allowed_risk_hints = _allowed_values(
        config,
        "allowed_risk_hints",
        DEFAULT_ALLOWED_RISK_HINTS,
    )

    validation_timestamp = datetime.now(UTC).isoformat()
    dataset_results = []

    for csv_filename in expected_csv_files:
        dataset_name = Path(csv_filename).stem
        dataset_path = input_path / csv_filename
        dataset_results.append(
            _validate_dataset(
                dataset_name=dataset_name,
                dataset_path=dataset_path,
                allowed_severities=allowed_severities,
                allowed_risk_hints=allowed_risk_hints,
            )
        )

    overall_score = _overall_score(dataset_results)
    summary = {
        "validation_timestamp": validation_timestamp,
        "input_dir": str(input_path),
        "datasets_validated": dataset_results,
        "missing_files": [],
        "overall_data_quality_score": overall_score,
    }

    write_data_quality_summary(summary_path, summary)
    write_data_quality_report(report_path, summary)
    return summary


def _validate_dataset(
    dataset_name: str,
    dataset_path: Path,
    allowed_severities: set[str],
    allowed_risk_hints: set[str],
) -> dict[str, Any]:
    checks = [check_file_exists(dataset_path), check_file_not_empty(dataset_path)]

    try:
        dataframe = pd.read_csv(dataset_path)
    except EmptyDataError:
        dataframe = pd.DataFrame()
        checks.append(make_check("csv_parseable", "failed", "CSV file has no parseable columns"))

    required_columns = PROCESSED_REQUIRED_COLUMNS[dataset_name]
    id_column = ID_COLUMNS[dataset_name]
    checks.extend(
        [
            check_required_columns(dataframe, required_columns),
            check_required_id_values(dataframe, id_column),
            check_duplicate_ids(dataframe, id_column),
            check_timestamp_column(dataframe),
            check_timestamp_parseable(dataframe),
            check_allowed_values(
                dataframe,
                "severity",
                allowed_severities,
                "severity_allowed_values",
            ),
            check_allowed_values(
                dataframe,
                "risk_hint",
                allowed_risk_hints,
                "risk_hint_allowed_values",
            ),
            check_column_exists(dataframe, "source_dataset", "source_dataset_column"),
            check_column_exists(dataframe, "ingestion_timestamp", "ingestion_timestamp_column"),
            check_source_dataset_value(dataframe, dataset_name),
        ]
    )

    failures = [check for check in checks if check["status"] == "failed"]
    warnings = [check for check in checks if check["status"] == "warning"]
    status = _dataset_status(failures, warnings)

    return {
        "dataset_name": dataset_name,
        "status": status,
        "record_count": int(len(dataframe)),
        "column_count": int(len(dataframe.columns)),
        "checks": checks,
        "warnings": warnings,
        "failures": failures,
        "data_quality_score": _data_quality_score(checks),
    }


def _dataset_status(failures: list[dict[str, Any]], warnings: list[dict[str, Any]]) -> str:
    if failures:
        return "failed"
    if warnings:
        return "warning"
    return "passed"


def _data_quality_score(checks: list[dict[str, Any]]) -> float:
    penalty = 0
    for check in checks:
        if check["status"] == "failed":
            penalty += 15
        elif check["status"] == "warning":
            penalty += 5
    return float(max(0, 100 - penalty))


def _overall_score(dataset_results: list[dict[str, Any]]) -> float:
    if not dataset_results:
        return 0.0
    total = sum(dataset["data_quality_score"] for dataset in dataset_results)
    return round(total / len(dataset_results), 1)


def _jsonl_to_csv(filename: str) -> str:
    return f"{Path(filename).stem}.csv"


def _allowed_values(config: dict[str, Any], key: str, default: set[str]) -> set[str]:
    values = config.get("validation", {}).get(key, sorted(default))
    if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
        raise ValueError(f"validation.{key} must be a list of strings")
    return {value.lower() for value in values}
