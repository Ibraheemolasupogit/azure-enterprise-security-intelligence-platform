"""Engine for local simulated GenAI investigation copilot outputs."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from security_intelligence.config import load_yaml_config
from security_intelligence.copilot.context import build_investigation_context
from security_intelligence.copilot.generator import generate_markdown
from security_intelligence.copilot.prompts import PROMPT_TEMPLATES
from security_intelligence.copilot.summary import write_copilot_context, write_copilot_report
from security_intelligence.paths import CONFIG_DIR, OUTPUT_DIR, REPORTS_DIR

REPORT_PATHS = {
    "investigation_summary": "copilot_investigation_summary.md",
    "soc_triage_note": "copilot_soc_triage_note.md",
    "executive_brief": "copilot_executive_brief.md",
    "remediation_plan": "copilot_remediation_plan.md",
    "compliance_evidence_summary": "copilot_compliance_evidence_summary.md",
}


def generate_copilot_briefs(
    outputs_dir: str | Path = OUTPUT_DIR,
    reports_dir: str | Path = REPORTS_DIR,
    context_path: str | Path = OUTPUT_DIR / "copilot_context.json",
    config_path: str | Path = CONFIG_DIR / "platform.yaml",
) -> dict[str, Any]:
    """Generate deterministic local simulated copilot briefs and context JSON."""
    config = load_yaml_config(config_path)
    settings = config.get("copilot", {})
    context = build_investigation_context(
        outputs_dir,
        max_security_findings=int(settings.get("max_security_findings", 5)),
        max_identity_findings=int(settings.get("max_identity_findings", 5)),
        max_risk_entities=int(settings.get("max_risk_entities", 10)),
    )
    prompt_types = list(PROMPT_TEMPLATES)
    context["prompt_types_generated"] = prompt_types
    write_copilot_context(context_path, context)

    generated_reports = {}
    reports_path = Path(reports_dir)
    for prompt_type in prompt_types:
        report_path = reports_path / REPORT_PATHS[prompt_type]
        content = generate_markdown(prompt_type, context)
        write_copilot_report(report_path, content)
        generated_reports[prompt_type] = str(report_path)

    return {
        "context_path": str(context_path),
        "generated_reports": generated_reports,
        "prompt_types_generated": prompt_types,
        "incident_context_id": context["incident_context_id"],
    }
