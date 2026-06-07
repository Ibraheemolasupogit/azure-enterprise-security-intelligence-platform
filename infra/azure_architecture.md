# Azure Architecture

This document maps the local-first security intelligence platform to a production-style Azure
architecture. It is a reference design only and does not claim that this repository is deployed to
Azure.

## Target Architecture

The production design centres on Microsoft Sentinel and Azure Monitor for security operations,
Microsoft Entra ID for identity governance, Microsoft Defender XDR for endpoint and cloud security
signals, Azure Data Lake Storage and Azure Data Explorer for analytical data, and Power BI or
Microsoft Fabric for reporting.

Azure AI Foundry, Azure OpenAI, Azure AI Search, and Azure Machine Learning are positioned as future
extension points after telemetry quality, governance, access control, and evidence management are
established.

## Service Mapping

| Local capability | Azure production service | Production role |
| --- | --- | --- |
| Synthetic raw telemetry | Event Hub, Azure Monitor, Log Analytics | Ingest platform, identity, endpoint, application, and cloud signals. |
| Processed datasets | Azure Data Lake Storage, Azure Data Explorer | Store raw and curated security analytics data. |
| Detection rules | Microsoft Sentinel | Run scheduled analytics, incident creation, and hunting workflows. |
| Identity governance checks | Microsoft Entra ID Governance, PIM, Conditional Access | Review access posture, privileged access, MFA, and guest exposure. |
| Security findings | Microsoft Defender XDR, Microsoft Sentinel | Combine endpoint, cloud, identity, and alert context. |
| Risk scoring | Azure Data Explorer, Azure Machine Learning | Support deterministic scoring and future ML-driven prioritisation. |
| Monitoring evidence | Azure Monitor, Application Insights, Sentinel workbooks | Track pipeline health, operational metrics, and evidence availability. |
| Dashboard exports | Power BI, Microsoft Fabric, Sentinel workbooks | Present SOC, governance, risk, and executive reporting views. |
| Copilot simulation | Azure AI Foundry, Azure OpenAI, Azure AI Search | Future governed investigation assistance and RAG over evidence. |
| Local config placeholders | Azure Key Vault, Managed Identity, RBAC | Protect secrets, enforce identity-based access, and remove static credentials. |

## Data Flow

Telemetry sources such as Microsoft Entra ID, Defender XDR, Defender for Cloud, applications, and
Azure control-plane logs stream into Event Hub, Azure Monitor, and Log Analytics. Microsoft Sentinel
normalises and correlates high-value security operations data.

Raw and curated analytics data can be exported to Azure Data Lake Storage. Azure Data Explorer can
support high-scale investigation, joins, time-series analysis, and dashboard serving. Reporting
outputs can be published to Power BI, Microsoft Fabric, or Sentinel workbooks.

## Security Operations Flow

1. Security signals arrive through Sentinel, Defender XDR, and Azure Monitor.
2. Sentinel analytics create alerts and incidents.
3. Identity governance evidence from Entra ID, PIM, Conditional Access, and access reviews enriches
   triage.
4. Deterministic and future ML-assisted scoring prioritises users, devices, resources, and incidents.
5. Analysts use Sentinel, Defender XDR, dashboards, and future copilot-style summaries to investigate.
6. Evidence is retained for incident response, governance reviews, and compliance reporting.

## Identity Governance Flow

Microsoft Entra ID is the identity system of record. Entra ID Governance provides access reviews,
entitlement management, and lifecycle controls. Privileged Identity Management governs elevated
roles, while Conditional Access and MFA policies reduce sign-in risk.

Identity evidence feeds security operations through Sentinel connectors, Log Analytics, Defender XDR
correlations, and dashboard reporting.

## Analytics And Reporting Flow

Curated security datasets support SOC dashboards, identity governance reviews, risk prioritisation,
operational health views, and executive reporting. Power BI and Microsoft Fabric can consume curated
tables from ADLS, ADX, or exported CSVs. Sentinel workbooks can provide operational views directly in
the SOC workspace.

## Future ML And GenAI Extension Points

Azure Machine Learning can host future anomaly detection and entity risk models. Azure AI Foundry and
Azure OpenAI can support governed investigation summaries, while Azure AI Search can index approved
evidence and reporting artifacts for future retrieval-augmented investigation workflows.

