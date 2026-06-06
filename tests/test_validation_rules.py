import pandas as pd

from security_intelligence.validation.rules import (
    check_duplicate_ids,
    check_required_columns,
    check_timestamp_parseable,
)


def test_validation_rules_detect_missing_required_columns() -> None:
    dataframe = pd.DataFrame([{"event_id": "one"}])

    result = check_required_columns(dataframe, ["event_id", "timestamp"])

    assert result["status"] == "failed"
    assert result["details"]["missing_columns"] == ["timestamp"]


def test_validation_rules_detect_duplicate_ids() -> None:
    dataframe = pd.DataFrame([{"event_id": "one"}, {"event_id": "one"}])

    result = check_duplicate_ids(dataframe, "event_id")

    assert result["status"] == "failed"
    assert result["details"]["duplicate_count"] == 1


def test_validation_rules_detect_invalid_timestamps() -> None:
    dataframe = pd.DataFrame([{"timestamp": "not-a-date"}])

    result = check_timestamp_parseable(dataframe)

    assert result["status"] == "failed"
    assert result["details"]["invalid_count"] == 1

