# Azure Mapping

This repository is local-first, but its modules and outputs are intentionally shaped around enterprise Azure security services.

| Repository area | Local responsibility | Azure service alignment |
| --- | --- | --- |
| `configs/platform.yaml` | Defines project metadata, local environment settings, output paths, and service mapping. | Azure Resource Manager design metadata, Azure Key Vault configuration boundary |
| `configs/detection_rules.yaml` | Stores placeholder detection rule metadata for future rule execution. | Microsoft Sentinel analytics rules |
| `configs/compliance_controls.yaml` | Stores placeholder control metadata and evidence expectations. | Azure Monitor evidence, compliance reporting workflows |
| `src/security_intelligence/config.py` | Loads local YAML configuration files. | Configuration foundation for future Azure-hosted services |
| `src/security_intelligence/cli.py` | Provides local operator commands for scaffold validation and configuration inspection. | Operational entry point similar to platform administration workflows |
| `data/raw/` | Future landing zone for synthetic raw telemetry. | Azure Data Lake Storage raw zone |
| `data/processed/` | Future curated local datasets. | Azure Data Lake Storage curated zone, Azure Data Explorer tables |
| `data/samples/` | Future sample datasets for demos and tests. | Microsoft Sentinel and Defender-style sample telemetry |
| `outputs/` | Future monitoring outputs and dashboard-ready files. | Azure Monitor, Power BI |
| `reports/` | Future investigation summaries and compliance evidence packages. | Microsoft Sentinel incidents, Microsoft Defender XDR investigations, compliance evidence |
| `notebooks/` | Future exploratory analytics and ML-readiness notebooks. | Azure Machine Learning workspaces |

## Service-Level View

| Azure service | Planned platform role |
| --- | --- |
| Microsoft Sentinel | Detection engineering, incident-style investigation outputs, security analytics workflow design |
| Microsoft Entra ID | Identity governance checks, privileged access review signals, risky sign-in analysis |
| Microsoft Defender XDR | Endpoint and incident context mapping for future investigation workflows |
| Azure Data Explorer | Scalable analytics model for security telemetry exploration |
| Azure Data Lake Storage | Raw and processed telemetry storage design |
| Azure Machine Learning | Future anomaly detection, risk scoring, and model evaluation workflows |
| Azure AI Foundry | Future GenAI-assisted investigation copilot design |
| Azure Monitor | Monitoring outputs and operational evidence |
| Power BI | Executive and operational dashboard exports |
| Azure Key Vault | Future secret management boundary |

