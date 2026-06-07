# Project Walkthrough

The Azure Enterprise Security Intelligence Platform is a local-first security analytics project that
models how an enterprise could collect, validate, analyze, prioritise, and report on security
telemetry across identity, endpoint, application, and cloud activity sources.

It is designed as a professional reference implementation, not a live Azure deployment. All data is
synthetic, all workflows run locally, and all AI-style outputs are generated with deterministic
templates rather than external services.

## Problem The Platform Solves

Security operations teams often face fragmented telemetry, high alert volume, weak visibility into
identity governance, manual evidence collection, and slow investigation workflows. Leaders need
clear risk summaries and reliable reporting, while analysts need traceable evidence and practical
next steps.

This project brings those concerns into one local pipeline that demonstrates security data
engineering, detection engineering, identity governance analytics, risk scoring, operational
evidence, dashboard exports, and Azure architecture alignment.

## Synthetic Telemetry

The telemetry generator creates artificial JSONL datasets for identity events, login events,
endpoint events, application events, security alerts, and cloud activity. Generation is
deterministic through a configurable seed, which makes demos and tests reproducible.

The telemetry includes normal activity and suspicious scenarios such as impossible travel, malware
detection, suspicious PowerShell activity, privileged role activation, guest exposure, and sensitive
cloud control-plane operations.

## Ingestion

The ingestion layer reads raw JSONL files, skips blank lines, reports invalid JSON with file and line
number, checks expected datasets, and writes processed CSV files. It adds ingestion metadata so later
stages can trace each record back to its source dataset and file.

## Validation

The validation layer checks processed CSV files for required columns, missing identifiers, duplicate
IDs, timestamp parseability, allowed severity values, allowed risk hints, and ingestion metadata. It
produces a machine-readable data quality summary and a Markdown evidence report.

## Detections

The detection layer applies deterministic rules to processed telemetry. It identifies impossible
travel, repeated failed logins, privileged role activation, suspicious PowerShell execution, malware,
suspicious cloud control-plane changes, and bulk application exports. Findings include severity,
confidence, MITRE ATT&CK mapping, recommended actions, and evidence.

## Identity Governance

The identity governance layer analyzes identity, login, application, cloud, and alert telemetry to
find dormant users, dormant privileged accounts, MFA gaps, guest exposure, role sprawl, risky
privilege assignments, and privileged cloud activity. It produces JSON findings, a CSV access review
table, and a governance report.

## Risk Scoring

Risk scoring combines threat findings, identity governance findings, and data quality context into
explainable entity risk records. Scores are deterministic and based on severity weights, governance
category weights, privileged-role modifiers, multiple-category modifiers, and overlap between
security and governance findings.

## Monitoring And Evidence

The monitoring layer checks whether major pipeline outputs exist, whether they are fresh, whether
record counts look reasonable, and whether validation, security, identity, and risk outputs contain
important posture signals. It creates an operational health summary, an evidence manifest, and a
Markdown operational evidence report.

## Local Copilot Simulation

The copilot layer builds a structured investigation context from security findings, identity
findings, risk scores, operational health, and evidence artifacts. It then generates local simulated
GenAI-style reports using deterministic templates. No LLM or external API is called.

Generated outputs include investigation summaries, SOC triage notes, executive briefs, remediation
plans, and compliance evidence summaries.

## Dashboard Exports

The dashboard layer turns platform outputs into dashboard-ready CSV files for tools such as Power
BI, Streamlit, spreadsheets, or other reporting surfaces. It also creates a dashboard summary and a
lightweight optional Streamlit placeholder.

## Azure Production Architecture

The infrastructure and architecture documentation explain how this local platform maps to a
production Azure design using Microsoft Sentinel, Azure Monitor, Event Hub, Log Analytics,
Microsoft Entra ID, Defender XDR, Azure Data Lake Storage, Azure Data Explorer, Power BI, Azure Key
Vault, Managed Identity, Azure Policy, Microsoft Purview, Azure AI Foundry, Azure AI Search, and
Azure Machine Learning.

The Bicep and Terraform files are reference skeletons only. They do not deploy real resources and do
not include real credentials, tenant IDs, or subscription IDs.

## Technical Capabilities Demonstrated

- Modular Python package design
- CLI-driven local workflow
- Deterministic synthetic data generation
- Security data engineering
- Detection engineering and MITRE mapping
- Identity governance analytics
- Explainable risk scoring
- Operational evidence generation
- Dashboard-ready reporting outputs
- Local GenAI-style investigation workflow
- Azure production architecture mapping
- Safe infrastructure-as-code design awareness
- Pytest and Ruff quality automation

