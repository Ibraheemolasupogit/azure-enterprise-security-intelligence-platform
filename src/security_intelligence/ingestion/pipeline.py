"""Raw-to-processed telemetry ingestion pipeline."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pandas as pd

from security_intelligence.config import load_yaml_config
from security_intelligence.ingestion.reader import read_jsonl
from security_intelligence.ingestion.summary import write_ingestion_summary
from security_intelligence.paths import CONFIG_DIR, DATA_DIR, OUTPUT_DIR


class MissingDatasetsError(FileNotFoundError):
    """Raised when required raw telemetry datasets are missing."""

    def __init__(self, missing_files: list[Path]) -> None:
        self.missing_files = missing_files
        missing = ", ".join(str(path) for path in missing_files)
        super().__init__(f"Missing required telemetry dataset files: {missing}")


def discover_expected_datasets(config_path: str | Path = CONFIG_DIR / "platform.yaml") -> list[str]:
    """Discover expected raw telemetry dataset filenames from platform configuration."""
    config = load_yaml_config(config_path)
    expected = config.get("telemetry_generation", {}).get("expected_datasets", [])

    if not isinstance(expected, list) or not all(isinstance(item, str) for item in expected):
        raise ValueError("telemetry_generation.expected_datasets must be a list of filenames")

    return expected


def validate_expected_files(input_dir: str | Path, expected_datasets: list[str]) -> list[Path]:
    """Return required dataset paths or raise a clear error for missing files."""
    input_path = Path(input_dir)
    dataset_paths = [input_path / filename for filename in expected_datasets]
    missing_files = [path for path in dataset_paths if not path.exists()]

    if missing_files:
        raise MissingDatasetsError(missing_files)

    return dataset_paths


def ingest_telemetry(
    input_dir: str | Path = DATA_DIR / "raw",
    output_dir: str | Path = DATA_DIR / "processed",
    summary_path: str | Path = OUTPUT_DIR / "ingestion_summary.json",
    config_path: str | Path = CONFIG_DIR / "platform.yaml",
) -> dict[str, Any]:
    """Ingest all expected raw JSONL telemetry datasets into processed CSV files."""
    input_path = Path(input_dir)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    ingestion_timestamp = datetime.now(UTC).isoformat()
    expected_datasets = discover_expected_datasets(config_path)
    dataset_paths = validate_expected_files(input_path, expected_datasets)

    dataset_summaries = []
    total_records = 0

    for source_file in dataset_paths:
        dataset_name = source_file.stem
        records = read_jsonl(source_file)
        dataframe = pd.DataFrame(records)
        dataframe["ingestion_timestamp"] = ingestion_timestamp
        dataframe["source_dataset"] = dataset_name
        dataframe["source_file"] = str(source_file)

        processed_file = output_path / f"{dataset_name}.csv"
        dataframe.to_csv(processed_file, index=False)

        record_count = len(dataframe)
        total_records += record_count
        dataset_summaries.append(
            {
                "dataset_name": dataset_name,
                "source_file": str(source_file),
                "processed_file": str(processed_file),
                "record_count": record_count,
                "column_count": len(dataframe.columns),
                "status": "processed",
                "missing_files": [],
            }
        )

    summary = {
        "ingestion_timestamp": ingestion_timestamp,
        "input_directory": str(input_path),
        "output_directory": str(output_path),
        "datasets": dataset_summaries,
        "missing_files": [],
        "total_records_ingested": total_records,
        "status": "success",
    }
    write_ingestion_summary(summary_path, summary)
    return summary

