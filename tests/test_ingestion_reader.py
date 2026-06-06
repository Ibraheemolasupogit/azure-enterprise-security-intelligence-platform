from pathlib import Path

import pytest

from security_intelligence.ingestion.reader import read_jsonl


def test_read_jsonl_reads_valid_file_and_skips_blank_lines(tmp_path: Path) -> None:
    jsonl_file = tmp_path / "events.jsonl"
    jsonl_file.write_text('{"event_id": "one"}\n\n{"event_id": "two"}\n', encoding="utf-8")

    records = read_jsonl(jsonl_file)

    assert records == [{"event_id": "one"}, {"event_id": "two"}]


def test_read_jsonl_raises_helpful_error_on_invalid_json(tmp_path: Path) -> None:
    jsonl_file = tmp_path / "events.jsonl"
    jsonl_file.write_text('{"event_id": "one"}\n{"event_id": \n', encoding="utf-8")

    with pytest.raises(ValueError, match=r"events\.jsonl.*line 2"):
        read_jsonl(jsonl_file)

