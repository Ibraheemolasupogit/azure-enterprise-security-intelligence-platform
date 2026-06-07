# Security Controls

This document outlines controls for a future Azure deployment. The current repository remains local
and synthetic.

## Identity And Access Controls

- Use Microsoft Entra ID as the identity provider.
- Require MFA and Conditional Access for privileged users.
- Use Privileged Identity Management for eligible administrative roles.
- Use least-privilege RBAC for Sentinel, Log Analytics, ADLS, ADX, Key Vault, and dashboards.
- Use managed identities for workload access instead of static credentials.
- Review guest access and privileged assignments on a defined cadence.

## Network Controls

- Restrict management plane access with RBAC and Conditional Access.
- Use private endpoints for storage, Key Vault, ADX, and AI services where required.
- Limit public network access for sensitive data services.
- Use diagnostic logging for network rule changes and control-plane events.

## Data Protection Controls

- Separate raw, curated, and reporting data zones.
- Encrypt data at rest with Microsoft-managed keys or customer-managed keys where required.
- Apply retention policies aligned to security operations and compliance needs.
- Classify and label sensitive evidence where Microsoft Purview is in scope.

## Logging And Monitoring Controls

- Enable Azure Monitor diagnostic settings for key services.
- Centralise high-value security logs in Log Analytics and Sentinel.
- Track ingestion health, alert volume, data quality, and dashboard freshness.
- Monitor administrative changes to Sentinel, Key Vault, storage, networking, and RBAC.

## Secrets Management Controls

- Store secrets in Azure Key Vault only.
- Prefer managed identities and federated credentials over client secrets.
- Enable Key Vault diagnostic logs and alert on suspicious access.
- Rotate secrets where secrets cannot be avoided.

## Compliance Evidence Controls

- Preserve evidence manifests, validation outputs, detection summaries, access review exports, and
  incident reports.
- Maintain clear source-to-report traceability.
- Align evidence artifacts to incident response, logging, identity governance, and risk management
  controls.

## Secure SDLC Controls

- Require code review for detection logic, infrastructure templates, and security controls.
- Run tests and static analysis before publishing changes.
- Keep deployment templates parameterised and environment-specific.
- Avoid secrets, tenant IDs, subscription IDs, and production URLs in source control.

