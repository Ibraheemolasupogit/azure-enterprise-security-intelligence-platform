# Environment Strategy

This document describes how the platform could be separated across local, dev, test, and production
environments.

## Environment Overview

| Environment | Data | Access | Monitoring | Retention | Approval gates |
| --- | --- | --- | --- | --- | --- |
| Local | Synthetic files only | Developer workstation | Local tests and reports | Short-lived or gitignored outputs | No cloud approval |
| Dev | Synthetic or approved sample data | Engineering team | Basic diagnostics | Short retention | Peer review |
| Test | Sanitised integration data | Security engineering and QA | Full validation and test alerts | Medium retention | Change approval |
| Prod | Approved production telemetry | SOC, identity, platform, and data roles | Full monitoring and evidence | Policy-driven retention | Formal release and security approval |

## Local

Local remains the source of design, tests, synthetic data generation, and portfolio documentation. It
must not contain real credentials or production data.

## Dev

Dev validates infrastructure templates, ingestion wiring, schema assumptions, and dashboard layouts.
It should use least-privilege access and short retention.

## Test

Test verifies alert logic, identity governance workflows, operational handover, evidence generation,
and rollback steps using non-production data.

## Prod

Production requires formal RBAC, managed identities, diagnostic coverage, retention policy, cost
monitoring, incident response runbooks, and compliance evidence handling.

