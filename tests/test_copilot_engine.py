import json
from pathlib import Path

from security_intelligence.copilot.engine import generate_copilot_briefs
from security_intelligence.copilot.prompts import LOCAL_SIMULATION_NOTE
from tests.test_copilot_support import build_full_evidence_chain


def test_copilot_engine_creates_context_json_and_reports(tmp_path: Path) -> None:
    outputs, reports = build_full_evidence_chain(tmp_path)
    context_path = outputs / "copilot_context.json"

    result = generate_copilot_briefs(outputs, reports, context_path)

    assert context_path.exists()
    context = json.loads(context_path.read_text(encoding="utf-8"))
    assert context["prompt_types_generated"]
    assert len(result["generated_reports"]) == 5
    for report_path in result["generated_reports"].values():
        path = Path(report_path)
        assert path.exists()
        content = path.read_text(encoding="utf-8")
        assert LOCAL_SIMULATION_NOTE in content
        assert "## Source Evidence Used" in content

