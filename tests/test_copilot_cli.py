from pathlib import Path

from security_intelligence.cli import main
from tests.test_copilot_support import build_full_evidence_chain


def test_cli_generate_copilot_briefs_runs_after_monitoring(tmp_path: Path, capsys) -> None:
    outputs, reports = build_full_evidence_chain(tmp_path)

    exit_code = main(
        [
            "generate-copilot-briefs",
            "--outputs-dir",
            str(outputs),
            "--reports-dir",
            str(reports),
            "--context-path",
            str(outputs / "copilot_context.json"),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Local simulated copilot briefs generated" in captured.out
    assert (outputs / "copilot_context.json").exists()
    assert (reports / "copilot_executive_brief.md").exists()

