from pathlib import Path

from security_intelligence.cli import main
from security_intelligence.telemetry.generator import generate_telemetry
from security_intelligence.telemetry.schemas import DATASET_FILENAMES


def test_cli_ingest_telemetry_runs_successfully_after_generation(
    tmp_path: Path, capsys
) -> None:
    raw_dir = tmp_path / "raw"
    processed_dir = tmp_path / "processed"
    summary_path = tmp_path / "outputs" / "ingestion_summary.json"
    generate_telemetry(raw_dir, days=7, users=8, seed=123)

    exit_code = main(
        [
            "ingest-telemetry",
            "--input-dir",
            str(raw_dir),
            "--output-dir",
            str(processed_dir),
            "--summary-path",
            str(summary_path),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Telemetry ingestion complete" in captured.out
    assert summary_path.exists()
    for dataset_name in DATASET_FILENAMES:
        assert (processed_dir / f"{dataset_name}.csv").exists()

