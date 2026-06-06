from pathlib import Path

import pytest

from security_intelligence.config import load_yaml_config


def test_load_yaml_config_reads_mapping(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text("project:\n  name: test\n", encoding="utf-8")

    config = load_yaml_config(config_file)

    assert config == {"project": {"name": "test"}}


def test_load_yaml_config_missing_file_raises(tmp_path: Path) -> None:
    missing_file = tmp_path / "missing.yaml"

    with pytest.raises(FileNotFoundError, match="Configuration file not found"):
        load_yaml_config(missing_file)


def test_load_yaml_config_invalid_yaml_raises(tmp_path: Path) -> None:
    config_file = tmp_path / "invalid.yaml"
    config_file.write_text("project: [broken\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid YAML"):
        load_yaml_config(config_file)

