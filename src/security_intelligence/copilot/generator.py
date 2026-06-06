"""Deterministic local Markdown generator for simulated copilot outputs."""

from __future__ import annotations

from typing import Any

from security_intelligence.copilot.prompts import LOCAL_SIMULATION_NOTE, PROMPT_TEMPLATES


def generate_markdown(prompt_type: str, context: dict[str, Any]) -> str:
    """Generate deterministic Markdown for a prompt type from structured context."""
    if prompt_type not in PROMPT_TEMPLATES:
        raise ValueError(f"Unsupported copilot prompt type: {prompt_type}")

    if prompt_type == "investigation_summary":
        return _investigation_summary(context)
    if prompt_type == "soc_triage_note":
        return _soc_triage_note(context)
    if prompt_type == "executive_brief":
        return _executive_brief(context)
    if prompt_type == "remediation_plan":
        return _remediation_plan(context)
    if prompt_type == "compliance_evidence_summary":
        return _compliance_evidence_summary(context)
    raise ValueError(f"Unsupported copilot prompt type: {prompt_type}")


def _header(prompt_type: str, context: dict[str, Any]) -> list[str]:
    template = PROMPT_TEMPLATES[prompt_type]
    return [
        f"# {template['title']}",
        "",
        f"Generated timestamp: {context['generated_timestamp']}",
        "",
        LOCAL_SIMULATION_NOTE,
        "",
        "## Source Evidence Used",
        "",
        *_evidence_lines(context),
        "",
    ]


def _investigation_summary(context: dict[str, Any]) -> str:
    lines = _header("investigation_summary", context)
    top_risk = context["top_risk_entities"][0] if context["top_risk_entities"] else {}
    lines.extend(
        [
            "## Structured Summary",
            "",
            (
                "The local platform identified "
                f"{context['key_metrics']['security_findings_total']} "
                "security findings and "
                f"{context['key_metrics']['identity_findings_total']} "
                "identity governance findings. "
                f"The highest-risk entity is {top_risk.get('entity_id', 'unknown')} with a "
                f"risk score of {top_risk.get('risk_score', 'n/a')}."
            ),
            "",
            "### What Happened",
            "",
            *_security_lines(context),
            "",
            "### Why It Matters",
            "",
            (
                "The findings combine endpoint, cloud, identity, and governance evidence, "
                "which indicates multiple operational domains may require review."
            ),
            "",
            "## Recommended Next Actions",
            "",
            "- Validate the top risk entities against security findings and identity evidence.",
            "- Triage critical security findings before medium-priority governance gaps.",
            "- Preserve generated reports as local investigation evidence.",
            "",
        ]
    )
    return "\n".join(lines)


def _soc_triage_note(context: dict[str, Any]) -> str:
    lines = _header("soc_triage_note", context)
    lines.extend(
        [
            "## Structured Summary",
            "",
            f"Priority: {context['operational_health']['overall_status']}",
            "",
            "### Analyst Evidence",
            "",
            *_risk_lines(context),
            "",
            "### Likely Impact",
            "",
            (
                "Critical and high risk entities may represent compromised accounts, "
                "malware-affected devices, risky cloud changes, or governance exposure."
            ),
            "",
            "## Recommended Next Actions",
            "",
            "- Start with the highest risk user and correlate security and governance evidence.",
            "- Review source event IDs listed in security findings and governance findings.",
            "- Confirm whether cloud control-plane activity was authorized.",
            "- Track triage notes alongside the evidence manifest.",
            "",
        ]
    )
    return "\n".join(lines)


def _executive_brief(context: dict[str, Any]) -> str:
    lines = _header("executive_brief", context)
    metrics = context["key_metrics"]
    lines.extend(
        [
            "## Structured Summary",
            "",
            (
                "The simulated platform is operating with warning-level health because "
                "critical security, identity, or risk signals are present in synthetic data."
            ),
            "",
            "### Business Risk",
            "",
            (
                f"There are {metrics['critical_risk_entities']} critical-risk entities, "
                f"{metrics['security_findings_total']} security findings, and "
                f"{metrics['identity_findings_total']} identity governance findings."
            ),
            "",
            "### Current Status",
            "",
            f"Operational health status: {metrics['overall_health_status']}.",
            "",
            "## Recommended Next Actions",
            "",
            "- Ask security operations to review the highest-risk entities first.",
            "- Ask identity owners to validate privileged access and MFA posture.",
            "- Use the evidence manifest for audit and executive follow-up.",
            "",
        ]
    )
    return "\n".join(lines)


def _remediation_plan(context: dict[str, Any]) -> str:
    lines = _header("remediation_plan", context)
    lines.extend(
        [
            "## Structured Summary",
            "",
            "The remediation plan is grouped by operational control area.",
            "",
            "## Identity And Access",
            "",
            "- Review privileged role assignments for top-risk users.",
            "- Re-enable or enforce MFA where governance findings indicate gaps.",
            "- Review guest identities for ownership, expiration, and sensitive access.",
            "",
            "## Endpoint Security",
            "",
            "- Isolate devices referenced by malware or suspicious process findings.",
            "- Review endpoint timelines for PowerShell and malware activity.",
            "",
            "## Cloud Control Plane",
            "",
            "- Validate diagnostic setting, role assignment, network rule, and Key Vault activity.",
            "- Restore secure configuration where unauthorized changes are identified.",
            "",
            "## Monitoring And Evidence",
            "",
            "- Refresh the full local pipeline after remediation.",
            "- Preserve operational health and evidence manifest outputs.",
            "",
            "## Governance And Compliance",
            "",
            "- Attach identity review CSV and risk scores to access review evidence.",
            "- Use report artifacts to support incident response and audit readiness.",
            "",
            "## Recommended Next Actions",
            "",
            "- Assign owners for each remediation area.",
            "- Re-run monitoring after changes and compare warning counts.",
            "",
        ]
    )
    return "\n".join(lines)


def _compliance_evidence_summary(context: dict[str, Any]) -> str:
    lines = _header("compliance_evidence_summary", context)
    artifacts = context["available_evidence"]
    lines.extend(
        [
            "## Structured Summary",
            "",
            f"{len(artifacts)} evidence artifacts are available for local audit review.",
            "",
            "### Evidence By Purpose",
            "",
        ]
    )
    for artifact in artifacts:
        lines.append(
            f"- {artifact.get('artifact_name')}: {artifact.get('purpose')} "
            f"({artifact.get('path')})"
        )
    lines.extend(
        [
            "",
            "## Recommended Next Actions",
            "",
            "- Use the evidence manifest as the audit index.",
            "- Map identity governance artifacts to access review evidence.",
            "- Map security findings and operational health to incident response evidence.",
            "- Map risk scores to risk management and executive reporting evidence.",
            "",
        ]
    )
    return "\n".join(lines)


def _evidence_lines(context: dict[str, Any]) -> list[str]:
    return [f"- {name}: {path}" for name, path in context["source_inputs"].items()]


def _security_lines(context: dict[str, Any]) -> list[str]:
    if not context["top_security_findings"]:
        return ["- No critical or high security findings were available."]
    return [
        (
            f"- {finding.get('finding_id')}: {finding.get('rule_name')} "
            f"({finding.get('severity')}) affecting {finding.get('entity_id')}"
        )
        for finding in context["top_security_findings"]
    ]


def _risk_lines(context: dict[str, Any]) -> list[str]:
    if not context["top_risk_entities"]:
        return ["- No risk-scored entities were available."]
    return [
        (
            f"- {record.get('risk_id')}: {record.get('entity_id')} "
            f"{record.get('risk_score')}/{record.get('risk_band')} "
            f"with {record.get('security_finding_count')} security findings and "
            f"{record.get('governance_finding_count')} governance findings"
        )
        for record in context["top_risk_entities"][:5]
    ]
