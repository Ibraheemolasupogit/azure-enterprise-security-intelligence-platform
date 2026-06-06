"""Prompt template registry for the local simulated investigation copilot."""

from __future__ import annotations

PROMPT_TEMPLATES = {
    "investigation_summary": {
        "title": "Copilot Investigation Summary",
        "purpose": (
            "Explain what happened, which entities are affected, why it matters, "
            "and what evidence supports the finding."
        ),
    },
    "soc_triage_note": {
        "title": "SOC Analyst Triage Note",
        "purpose": "Provide analyst-ready priority, evidence, likely impact, and next steps.",
    },
    "executive_brief": {
        "title": "Executive Incident Brief",
        "purpose": (
            "Summarize business risk, affected areas, current status, and recommended "
            "action in non-technical language."
        ),
    },
    "remediation_plan": {
        "title": "Copilot Remediation Plan",
        "purpose": (
            "Generate practical remediation steps mapped to identity, endpoint, cloud, "
            "monitoring, governance, and compliance controls."
        ),
    },
    "compliance_evidence_summary": {
        "title": "Compliance Evidence Summary",
        "purpose": (
            "Summarize which evidence artifacts support audit, incident response, "
            "identity governance, and risk management."
        ),
    },
}

LOCAL_SIMULATION_NOTE = (
    "Local simulated GenAI note: this report was generated deterministically from "
    "local synthetic platform outputs. No Azure OpenAI, Azure AI Foundry, OpenAI, "
    "LangChain, Microsoft Graph, or external API calls were made."
)

