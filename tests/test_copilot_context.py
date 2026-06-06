from pathlib import Path

from security_intelligence.copilot.context import build_investigation_context
from tests.test_copilot_support import build_full_evidence_chain


def test_context_builder_loads_expected_inputs(tmp_path: Path) -> None:
    outputs, _ = build_full_evidence_chain(tmp_path)

    context = build_investigation_context(outputs)

    assert context["incident_context_id"].startswith("CTX-")
    assert context["source_inputs"]["security_findings"].endswith("security_findings.json")
    assert context["operational_health"]["overall_status"]
    assert context["available_evidence"]


def test_context_builder_extracts_top_security_findings(tmp_path: Path) -> None:
    outputs, _ = build_full_evidence_chain(tmp_path)

    context = build_investigation_context(outputs, max_security_findings=3)

    assert len(context["top_security_findings"]) == 3
    assert all(
        finding["severity"] in {"critical", "high"}
        for finding in context["top_security_findings"]
    )


def test_context_builder_extracts_top_risk_entities(tmp_path: Path) -> None:
    outputs, _ = build_full_evidence_chain(tmp_path)

    context = build_investigation_context(outputs, max_risk_entities=4)

    assert len(context["top_risk_entities"]) == 4
    assert context["top_risk_entities"][0]["risk_score"] >= context["top_risk_entities"][-1][
        "risk_score"
    ]

