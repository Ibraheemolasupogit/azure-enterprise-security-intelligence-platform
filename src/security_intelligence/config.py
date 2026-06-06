"""Configuration loading helpers for the local platform."""

from pathlib import Path
from typing import Any

import yaml


def load_yaml_config(path: str | Path) -> dict[str, Any]:
    """Load a YAML configuration file and return its parsed contents.

    Args:
        path: Path to a YAML file.

    Raises:
        FileNotFoundError: If the configuration file does not exist.
        ValueError: If the YAML is invalid or does not contain a mapping.
    """
    config_path = Path(path)

    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    try:
        with config_path.open("r", encoding="utf-8") as file:
            data = yaml.safe_load(file)
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML in configuration file: {config_path}") from exc

    if data is None:
        return {}

    if not isinstance(data, dict):
        raise ValueError(f"YAML configuration must be a mapping: {config_path}")

    return data

