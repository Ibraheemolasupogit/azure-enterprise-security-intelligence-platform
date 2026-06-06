"""Logging setup utilities."""

import logging


def setup_logging(level: int | str = logging.INFO) -> None:
    """Configure basic console logging for local development."""
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
    )

