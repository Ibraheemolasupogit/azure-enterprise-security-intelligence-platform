# Limitations And Future Work

This project is intentionally local-first. The limitations below are design boundaries, not hidden
deployment gaps.

## Current Limitations

- Synthetic data only
- No live Azure deployment
- No real Microsoft Sentinel connector
- No real Microsoft Graph or Entra ID connector
- No real Microsoft Defender XDR connector
- No real Azure Monitor diagnostic ingestion
- No real Power BI API integration
- Local simulated GenAI-style outputs only
- No Azure OpenAI, Azure AI Foundry, OpenAI, LangChain, or external API calls
- Deterministic scoring, not trained machine learning
- Lightweight local Streamlit placeholder only
- Terraform and Bicep files are reference skeletons only
- No production CI/CD deployment pipeline
- No production secrets, tenant IDs, subscription IDs, or endpoints

## Future Work

- Deploy a controlled sandbox version in Azure
- Add Microsoft Sentinel connector integration
- Add Microsoft Entra ID and Microsoft Graph integration
- Add Microsoft Defender XDR integration
- Add Azure Monitor and Event Hub ingestion patterns
- Add Azure Data Explorer analytics tables and KQL examples
- Add Azure Machine Learning anomaly detection models
- Add Azure AI Foundry RAG investigation assistant with approved evidence sources
- Build a Power BI dashboard from the exported datasets
- Add CI/CD pipeline automation
- Expand policy-as-code and detection-as-code patterns
- Add production-grade RBAC, private endpoints, and managed identity design
- Add more compliance mappings and control evidence packs

