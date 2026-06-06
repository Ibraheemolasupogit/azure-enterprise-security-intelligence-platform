from pathlib import Path

from security_intelligence.copilot.context import build_investigation_context
from security_intelligence.copilot.generator import generate_markdown
from security_intelligence.copilot.prompts import LOCAL_SIMULATION_NOTE, PROMPT_TEMPLATES
from tests.test_copilot_support import build_full_evidence_chain


def test_local_generator_creates_markdown_for_each_prompt_type(tmp_path: Path) -> None:
    outputs, _ = build_full_evidence_chain(tmp_path)
    context = build_investigation_context(outputs)

    for prompt_type in PROMPT_TEMPLATES:
        markdown = generate_markdown(prompt_type, context)
        assert markdown.startswith("# ")
        assert LOCAL_SIMULATION_NOTE in markdown
        assert "## Source Evidence Used" in markdown
        assert "security_findings.json" in markdown

