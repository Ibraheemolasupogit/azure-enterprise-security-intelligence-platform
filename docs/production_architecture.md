# Production Azure Architecture

The Azure Enterprise Security Intelligence Platform is implemented locally today, but its design maps
to a production Azure security architecture. This document explains how the repository could evolve
from synthetic files and deterministic local analytics into a governed enterprise security
intelligence platform.

This is a reference architecture. The repository does not deploy Azure resources, connect to a real
tenant, or process production data.

## Architecture Goals

- Centralise security telemetry for investigation and reporting.
- Support SOC workflows through Microsoft Sentinel and Microsoft Defender XDR.
- Strengthen Zero Trust identity governance with Microsoft Entra ID signals.
- Preserve audit-ready evidence for compliance, risk, and incident response.
- Provide dashboard-ready analytics for SOC, governance, and executive reporting.
- Prepare for future Azure Machine Learning and Azure AI Foundry workflows.

## Production Service Map

| Architecture area | Azure services | Role |
| --- | --- | --- |
| Telemetry ingestion | Event Hub, Azure Monitor, Log Analytics, Microsoft Sentinel | Collect and normalise security events. |
| Identity governance | Microsoft Entra ID, Entra ID Governance, Conditional Access, PIM | Govern access, MFA, guests, and privileged roles. |
| Endpoint and cloud security | Microsoft Defender XDR, Defender for Endpoint, Defender for Cloud | Provide endpoint, incident, and cloud posture signals. |
| Data platform | Azure Data Lake Storage, Azure Data Explorer | Store, curate, query, and correlate security data. |
| Risk and analytics | Azure Data Explorer, Azure Machine Learning | Prioritise entities and prepare future anomaly workflows. |
| Investigation assistance | Azure AI Foundry, Azure OpenAI, Azure AI Search | Future governed investigation summaries and evidence retrieval. |
| Governance and secrets | Azure Key Vault, Managed Identity, RBAC, Azure Policy, Microsoft Purview | Protect secrets, enforce access, and support compliance. |
| Monitoring and reporting | Azure Monitor, Application Insights, Sentinel workbooks, Power BI | Track platform health and communicate outcomes. |

## Evolution From Local To Azure

The local pipeline currently follows this pattern:

1. Generate synthetic telemetry.
2. Ingest raw JSONL into processed CSV.
3. Validate data quality.
4. Run deterministic detections.
5. Run identity governance checks.
6. Score risk.
7. Generate operational evidence.
8. Produce local simulated copilot briefs.
9. Export dashboard-ready datasets.

A production Azure implementation would preserve those logical stages while replacing local files
with managed services, secure identities, governed storage, and operational monitoring.

## Production Data Flow

Security data would arrive from Microsoft Entra ID, Microsoft Defender XDR, Defender for Cloud,
Azure activity logs, SaaS applications, and custom sources. Event Hub and Azure Monitor would support
streaming and diagnostic ingestion. Log Analytics and Microsoft Sentinel would provide SIEM-style
analytics and incident workflows.

Curated data can be written to Azure Data Lake Storage for durable evidence and Azure Data Explorer
for scalable investigation queries. Power BI, Microsoft Fabric, and Sentinel workbooks can expose
dashboard views for executives, SOC users, identity teams, and risk stakeholders.

## Security And Governance

Production access should use Microsoft Entra ID, managed identities, RBAC, PIM, Conditional Access,
and Key Vault. Azure Policy can enforce diagnostic settings, allowed locations, encryption posture,
and tagging. Microsoft Purview can support data classification and governance where required.

## Future AI Readiness

Future Azure AI Foundry, Azure OpenAI, Azure AI Search, and Azure Machine Learning capabilities
should be added only after data quality, access controls, evidence traceability, and human review
workflows are mature. The local copilot layer demonstrates investigation patterns without making any
external API calls.

