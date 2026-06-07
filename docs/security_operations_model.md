# Security Operations Model

This operating model describes how a production Azure version of the platform could support SOC,
identity governance, incident response, executive reporting, compliance evidence, and future
GenAI-assisted investigation workflows.

The current repository remains local-first and synthetic.

## SOC Analyst Workflow

1. Review Microsoft Sentinel incidents, Defender XDR alerts, and platform risk summaries.
2. Triage high and critical findings first.
3. Correlate user, device, application, and cloud-resource evidence.
4. Review MITRE ATT&CK mapping, evidence references, and recommended actions.
5. Escalate confirmed incidents and document response actions.

## Identity Governance Workflow

1. Review privileged role assignments, PIM activations, MFA gaps, guest exposure, and dormant users.
2. Prioritise accounts with overlapping security findings and governance findings.
3. Run access reviews for high-risk users and guest accounts.
4. Remediate excessive privilege, missing MFA, risky assignments, and stale access.
5. Preserve identity review evidence for audit and Zero Trust reporting.

## Incident Response Workflow

1. Confirm alert scope and affected entities.
2. Contain risky accounts, devices, cloud resources, or application tokens.
3. Collect evidence from Sentinel, Defender XDR, Entra ID, Azure Monitor, and platform reports.
4. Execute remediation and recovery steps.
5. Create final incident notes, lessons learned, and compliance evidence.

## Executive Reporting Workflow

Executives need trend-level and business-friendly views: total findings, critical risks, affected
business areas, identity governance posture, data quality, evidence readiness, and remediation
progress. Power BI, Fabric, or Sentinel workbooks can present these summaries from curated outputs.

## Compliance Evidence Workflow

Evidence artifacts should trace from source telemetry to validation, detection, identity governance,
risk scoring, monitoring, and final reports. Evidence should align to logging and monitoring,
incident response, identity governance, risk management, and evidence generation controls.

## GenAI-Assisted Investigation Workflow

Future GenAI-assisted workflows can summarise incidents, explain evidence, generate triage notes,
and draft remediation plans. Any production use should include approved data sources, access
controls, logging, human review, prompt governance, and evidence traceability.

