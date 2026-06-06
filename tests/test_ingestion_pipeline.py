import json
from pathlib import Path

import pandas as pd
import pytest

from security_intelligence.ingestion.pipeline import MissingDatasetsError, ingest_telemetry
from security_intelligence.telemetry.generator import generate_telemetry
from security_intelligence.telemetry.schemas import DATASET_FILENAMES


def test_ingestion_pipeline_creates_processed_csv_files_and_summary(tmp_path: Path) -> None:
    raw_dir = tmp_path / "raw"
    processed_dir = tmp_path / "processed"
    summary_path = tmp_path / "outputs" / "ingestion_summary.json"
    generate_telemetry(raw_dir, days=7, users=8, seed=123)

    summary = ingest_telemetry(raw_dir, processed_dir, summary_path)

    assert summary_path.exists()
    saved_summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert saved_summary["total_records_ingested"] == summary["total_records_ingested"]
    assert saved_summary["status"] == "success"

    for dataset_name in DATASET_FILENAMES:
        processed_file = processed_dir / f"{dataset_name}.csv"
        assert processed_file.exists()
        dataframe = pd.read_csv(processed_file)
        assert "ingestion_timestamp" in dataframe.columns
        assert "source_dataset" in dataframe.columns
        assert "source_file" in dataframe.columns
        assert set(dataframe["source_dataset"]) == {dataset_name}


def test_ingestion_pipeline_reports_missing_input_files(tmp_path: Path) -> None:
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()

    with pytest.raises(MissingDatasetsError, match="identity_events.jsonl"):
        ingest_telemetry(raw_dir, tmp_path / "processed", tmp_path / "summary.json")

