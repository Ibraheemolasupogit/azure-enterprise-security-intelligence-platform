"""Safe JSONL reading utilities for telemetry ingestion."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    """Read a JSONL file into dictionaries.

    Blank lines are skipped. Invalid JSON raises a ValueError that includes the
    source file path and line number so operators can fix raw input quickly.
    """
    jsonl_path = Path(path)
    records: list[dict[str, Any]] = []

    with jsonl_path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            stripped = line.strip()
            if not stripped:
                continue

            try:
                record = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON in {jsonl_path} at line {line_number}: {exc.msg}"
                ) from exc

            if not isinstance(record, dict):
                raise ValueError(
                    f"Invalid JSONL record in {jsonl_path} at line {line_number}: "
                    "expected an object"
                )

            records.append(record)

    return records

