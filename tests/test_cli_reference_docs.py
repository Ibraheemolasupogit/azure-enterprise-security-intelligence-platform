from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


EXPECTED_COMMANDS = [
    "health-check",
    "show-config",
    "generate-telemetry",
    "ingest-telemetry",
    "validate-telemetry",
    "run-detections",
    "run-identity-checks",
    "score-risk",
    "monitor-platform",
    "generate-copilot-briefs",
    "export-dashboard-data",
]


def test_cli_reference_documents_all_commands() -> None:
    cli_reference = (ROOT / "docs/cli_reference.md").read_text(encoding="utf-8")

    for command in EXPECTED_COMMANDS:
        assert command in cli_reference


def test_local_demo_includes_full_pipeline_commands() -> None:
    local_demo = (ROOT / "LOCAL_DEMO.md").read_text(encoding="utf-8")

    for command in EXPECTED_COMMANDS:
        assert command in local_demo

