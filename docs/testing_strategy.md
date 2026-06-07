# Testing Strategy

The project uses pytest and Ruff to keep the local-first platform reliable, readable, and safe to
refactor.

## Pytest Coverage By Layer

Tests cover:

- Configuration loading and CLI health checks
- Synthetic telemetry generation and deterministic output
- JSONL reading and ingestion pipeline behavior
- Data validation rules and validation outputs
- Threat detection rules and detection engine outputs
- Identity governance checks and review exports
- Risk scoring logic, risk bands, and score caps
- Monitoring health checks and evidence manifest generation
- Local copilot context building and Markdown generation
- Dashboard export metrics and CSV outputs
- Architecture and documentation file coverage

## Deterministic Tests

Synthetic telemetry generation uses configurable seeds. This makes test data repeatable while still
representing realistic security events. Determinism also keeps dashboard metrics, findings, and risk
outputs stable enough for automated checks.

## Safe Synthetic Data

Tests use synthetic data and temporary directories. They do not require real users, production
telemetry, tenant IDs, subscription IDs, cloud credentials, or external network calls.

## Ruff Quality Checks

Ruff enforces import order and Python style expectations. It keeps the codebase consistent across
platform modules, tests, and generated support files.

## No Cloud Credentials Required

The test suite does not require Azure CLI, Microsoft Graph, Defender XDR, Sentinel, Terraform,
Bicep, Power BI, Azure OpenAI, or Azure AI Foundry credentials. Infrastructure templates and cloud
architecture docs are validated only as local files.

## Refactoring And Portfolio Trust

The tests provide a safety net for changing individual layers without breaking the end-to-end local
workflow. They also make the repository easier to review because the platform behavior can be
verified locally with standard Python tooling.

