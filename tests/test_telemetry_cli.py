from pathlib import Path

from security_intelligence.cli import main
from security_intelligence.telemetry.schemas import DATASET_FILENAMES


def test_cli_generate_telemetry_runs_successfully(tmp_path: Path, capsys) -> None:
    exit_code = main(
        [
            "generate-telemetry",
            "--output-dir",
            str(tmp_path),
            "--days",
            "7",
            "--users",
            "8",
            "--seed",
            "123",
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Synthetic telemetry generated" in captured.out
    for filename in DATASET_FILENAMES.values():
        assert (tmp_path / filename).exists()

