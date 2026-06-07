# Deployment Plan

This plan describes how the local-first platform could evolve into a production Azure architecture.
It is intentionally non-executable and does not deploy resources.

## Phased Approach

| Phase | Focus | Outcome |
| --- | --- | --- |
| 1 | Foundation | Resource groups, naming, tags, RBAC model, Key Vault, Log Analytics, and storage zones. |
| 2 | Security telemetry | Azure Monitor diagnostics, Event Hub ingestion, Sentinel connectors, and Defender integrations. |
| 3 | Data platform | ADLS raw and curated zones, ADX analytical tables, retention policies, and data access controls. |
| 4 | Detection and governance | Sentinel analytics, identity governance reporting, PIM evidence, and Conditional Access signals. |
| 5 | Risk and reporting | Risk scoring jobs, Sentinel workbooks, Power BI datasets, and executive reporting packs. |
| 6 | Future AI | Azure ML, Azure AI Foundry, Azure OpenAI, and Azure AI Search after governance approval. |

## Environment Strategy

Dev, test, and prod should use separate resource groups, managed identities, storage accounts, Log
Analytics workspaces, and Key Vault instances. Production should have stricter RBAC, longer evidence
retention, tighter diagnostic coverage, and formal approval gates.

## Prerequisites

- Approved Azure tenant, subscription, region, and naming standards
- Security and compliance requirements for telemetry retention
- RBAC model for SOC, identity, data, platform, and executive users
- Data classification and evidence handling requirements
- Network and private endpoint strategy where required
- Budget, tagging, and cost management policies

## Deployment Sequence

1. Create resource groups and baseline policy assignments.
2. Provision Log Analytics, storage, Key Vault, and managed identities.
3. Enable Microsoft Sentinel on the security operations workspace.
4. Configure Defender XDR, Defender for Cloud, Entra ID, and Azure Monitor connectors.
5. Configure diagnostic settings and Event Hub routes for required telemetry.
6. Create ADLS zones and optional ADX tables for curated analytics.
7. Publish Sentinel analytics, workbooks, and reporting data products.
8. Validate access, retention, alerts, dashboards, and evidence generation.

## Validation Checks

- No static secrets are stored in source control or deployment parameters.
- Managed identities and RBAC are used for service access.
- Logs arrive in Log Analytics and Sentinel with expected schemas.
- Storage lifecycle, retention, and access controls match policy.
- Dashboards and evidence reports reconcile with source records.
- Security alerts and incident workflows are tested in non-production first.

## Rollback Considerations

Rollback should prioritise disabling new ingestion routes, reverting analytics rules, restoring prior
dashboard versions, and preserving evidence. Destructive cleanup of storage, logs, and audit records
must follow retention and legal hold requirements.

## Operational Handover

Production handover should include runbooks, support ownership, alert routing, dashboard ownership,
evidence retention expectations, access review cadence, cost monitoring, and incident response
contacts.

