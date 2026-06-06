import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from security_intelligence.monitoring.health import (
    artifact_freshness_warning,
    check_artifact_stage,
)


def test_artifact_existence_check_passes_for_existing_file(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.json"
    artifact.write_text("{}", encoding="utf-8")

    result = check_artifact_stage(
        stage="validation",
        path=artifact,
        monitoring_timestamp="2026-06-06T12:00:00+00:00",
        freshness_hours=24,
        record_count=1,
        key_metrics={},
    )

    assert result["artifact_exists"] is True
    assert result["status"] == "passed"


def test_missing_critical_output_produces_failed_stage(tmp_path: Path) -> None:
    result = check_artifact_stage(
        stage="risk_scoring",
        path=tmp_path / "missing.json",
        monitoring_timestamp="2026-06-06T12:00:00+00:00",
        freshness_hours=24,
        record_count=None,
        key_metrics={},
    )

    assert result["status"] == "failed"
    assert result["failures"]


def test_stale_artifact_produces_freshness_warning(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.json"
    artifact.write_text("{}", encoding="utf-8")
    old_time = (datetime.now(UTC) - timedelta(hours=48)).timestamp()
    os.utime(artifact, (old_time, old_time))

    warning = artifact_freshness_warning(artifact, freshness_hours=24)

    assert warning is not None
    assert "stale" in warning

