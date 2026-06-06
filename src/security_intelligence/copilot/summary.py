"""Copilot context and report writers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def write_copilot_context(path: str | Path, context: dict[str, Any]) -> None:
    """Write copilot investigation context JSON."""
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(context, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_copilot_report(path: str | Path, content: str) -> None:
    """Write a copilot Markdown report."""
    report_path = Path(path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(content, encoding="utf-8")

