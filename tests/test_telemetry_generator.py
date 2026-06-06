import json
from pathlib import Path

from security_intelligence.telemetry.generator import generate_telemetry
from security_intelligence.telemetry.schemas import DATASET_FILENAMES, REQUIRED_FIELDS


def _read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_generate_telemetry_creates_all_expected_files(tmp_path: Path) -> None:
    counts = generate_telemetry(tmp_path, days=7, users=8, seed=123)

    assert set(counts) == set(DATASET_FILENAMES)
    for filename in DATASET_FILENAMES.values():
        assert (tmp_path / filename).exists()


def test_generated_jsonl_files_are_valid_json(tmp_path: Path) -> None:
    generate_telemetry(tmp_path, days=7, users=8, seed=123)

    for filename in DATASET_FILENAMES.values():
        records = _read_jsonl(tmp_path / filename)
        assert records
        assert all(isinstance(record, dict) for record in records)


def test_generated_records_contain_required_fields(tmp_path: Path) -> None:
    generate_telemetry(tmp_path, days=7, users=8, seed=123)

    for dataset_name, filename in DATASET_FILENAMES.items():
        first_record = _read_jsonl(tmp_path / filename)[0]
        assert set(REQUIRED_FIELDS[dataset_name]).issubset(first_record)


def test_generation_is_deterministic_with_same_seed(tmp_path: Path) -> None:
    first_output = tmp_path / "first"
    second_output = tmp_path / "second"

    first_counts = generate_telemetry(first_output, days=10, users=10, seed=42)
    second_counts = generate_telemetry(second_output, days=10, users=10, seed=42)

    assert first_counts == second_counts
    for filename in DATASET_FILENAMES.values():
        assert (first_output / filename).read_text(encoding="utf-8") == (
            second_output / filename
        ).read_text(encoding="utf-8")

