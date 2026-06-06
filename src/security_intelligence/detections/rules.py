"""Deterministic threat detection rule implementations."""

from __future__ import annotations

from typing import Any

import pandas as pd

from security_intelligence.detections.models import build_finding

HIGH_PRIVILEGE_ROLES = {"global admin", "security administrator", "privileged role admin"}
SUSPICIOUS_CLOUD_OPERATIONS = {
    "diagnostic_setting_disabled",
    "network_rule_changed",
    "role_assignment_created",
    "key_vault_secret_accessed",
}
HIGH_RISK_VALUES = {"high", "critical"}


def detect_impossible_travel(
    login_events: pd.DataFrame,
    rule: dict[str, Any],
    detection_timestamp: str,
) -> list[dict[str, Any]]:
    """Detect same-user logins from different countries within a short window."""
    if login_events.empty:
        return []

    window_minutes = int(rule.get("window_minutes", 120))
    findings = []
    dataframe = login_events.copy()
    dataframe["parsed_timestamp"] = pd.to_datetime(dataframe["timestamp"], errors="coerce")
    dataframe = dataframe.dropna(subset=["parsed_timestamp"]).sort_values(
        ["user_id", "parsed_timestamp"]
    )
    successful = dataframe[dataframe["login_status"].astype(str).str.lower() == "success"]

    for _, user_events in successful.groupby("user_id"):
        previous = None
        for _, event in user_events.iterrows():
            if previous is not None:
                minutes = (
                    event["parsed_timestamp"] - previous["parsed_timestamp"]
                ).total_seconds() / 60
                if (
                    0 <= minutes <= window_minutes
                    and str(event["country"]) != str(previous["country"])
                ):
                    findings.append(
                        build_finding(
                            detection_timestamp=detection_timestamp,
                            rule_id=rule["rule_id"],
                            rule_name=rule["rule_name"],
                            severity=rule["severity"],
                            confidence=0.9,
                            entity_type="user",
                            entity_id=str(event["user_id"]),
                            user_id=str(event["user_id"]),
                            source_dataset="login_events",
                            event_id=str(event["event_id"]),
                            description=(
                                "User logged in from different countries within "
                                f"{window_minutes} minutes."
                            ),
                            mitre_tactic=rule["mitre_tactic"],
                            mitre_technique=rule["mitre_technique"],
                            recommended_action="Review sign-in context and confirm user activity.",
                            evidence={
                                "current_event_id": str(event["event_id"]),
                                "previous_event_id": str(previous["event_id"]),
                                "current_country": str(event["country"]),
                                "previous_country": str(previous["country"]),
                                "minutes_between_logins": round(minutes, 2),
                            },
                        )
                    )
            previous = event
    return findings


def detect_repeated_failed_login(
    login_events: pd.DataFrame,
    rule: dict[str, Any],
    detection_timestamp: str,
) -> list[dict[str, Any]]:
    """Detect multiple failed logins for the same user within a configured window."""
    if login_events.empty:
        return []

    threshold = int(rule.get("threshold", 3))
    window_minutes = int(rule.get("window_minutes", 60))
    findings = []
    dataframe = login_events.copy()
    dataframe["parsed_timestamp"] = pd.to_datetime(dataframe["timestamp"], errors="coerce")
    failed = dataframe[
        (dataframe["login_status"].astype(str).str.lower() == "failure")
        & dataframe["parsed_timestamp"].notna()
    ].sort_values(["user_id", "parsed_timestamp"])

    for user_id, user_events in failed.groupby("user_id"):
        rows = list(user_events.iterrows())
        for index, (_, start_event) in enumerate(rows):
            window_end = start_event["parsed_timestamp"] + pd.Timedelta(minutes=window_minutes)
            events_in_window = [
                event
                for _, event in rows[index:]
                if start_event["parsed_timestamp"] <= event["parsed_timestamp"] <= window_end
            ]
            if len(events_in_window) >= threshold:
                last_event = events_in_window[-1]
                findings.append(
                    build_finding(
                        detection_timestamp=detection_timestamp,
                        rule_id=rule["rule_id"],
                        rule_name=rule["rule_name"],
                        severity=rule["severity"],
                        confidence=0.85,
                        entity_type="user",
                        entity_id=str(user_id),
                        user_id=str(user_id),
                        source_dataset="login_events",
                        event_id=str(last_event["event_id"]),
                        description=(
                            f"{len(events_in_window)} failed logins detected within "
                            f"{window_minutes} minutes."
                        ),
                        mitre_tactic=rule["mitre_tactic"],
                        mitre_technique=rule["mitre_technique"],
                        recommended_action=(
                            "Review authentication failures and enforce MFA controls."
                        ),
                        evidence={
                            "failed_event_ids": [
                                str(event["event_id"]) for event in events_in_window
                            ],
                            "threshold": threshold,
                            "window_minutes": window_minutes,
                        },
                    )
                )
                break
    return findings


def detect_privileged_role_activation(
    identity_events: pd.DataFrame,
    rule: dict[str, Any],
    detection_timestamp: str,
) -> list[dict[str, Any]]:
    """Detect privileged role assignment or activation events."""
    if identity_events.empty:
        return []

    event_types = {"privileged_role_activated", "role_assigned"}
    findings = []
    for _, event in identity_events.iterrows():
        role = str(event.get("role", ""))
        if (
            str(event.get("event_type", "")).lower() in event_types
            and role.lower() in HIGH_PRIVILEGE_ROLES
        ):
            findings.append(
                build_finding(
                    detection_timestamp=detection_timestamp,
                    rule_id=rule["rule_id"],
                    rule_name=rule["rule_name"],
                    severity=rule["severity"],
                    confidence=0.8,
                    entity_type="user",
                    entity_id=str(event["user_id"]),
                    user_id=str(event["user_id"]),
                    source_dataset="identity_events",
                    event_id=str(event["event_id"]),
                    description=f"High-privilege role activity detected for role: {role}.",
                    mitre_tactic=rule["mitre_tactic"],
                    mitre_technique=rule["mitre_technique"],
                    recommended_action="Review approval trail and remove unnecessary privilege.",
                    evidence={
                        "event_type": str(event.get("event_type")),
                        "role": role,
                        "user_principal_name": str(event.get("user_principal_name")),
                    },
                )
            )
    return findings


def detect_suspicious_powershell(
    endpoint_events: pd.DataFrame,
    rule: dict[str, Any],
    detection_timestamp: str,
) -> list[dict[str, Any]]:
    """Detect PowerShell execution or suspicious process activity."""
    if endpoint_events.empty:
        return []

    findings = []
    for _, event in endpoint_events.iterrows():
        event_type = str(event.get("event_type", "")).lower()
        severity = str(event.get("severity", "")).lower()
        if event_type in {"powershell_execution", "suspicious_process"}:
            findings.append(
                build_finding(
                    detection_timestamp=detection_timestamp,
                    rule_id=rule["rule_id"],
                    rule_name=rule["rule_name"],
                    severity=severity if severity in HIGH_RISK_VALUES else rule["severity"],
                    confidence=0.8 if severity in HIGH_RISK_VALUES else 0.65,
                    entity_type="device",
                    entity_id=str(event["device_id"]),
                    user_id=str(event.get("user_id")),
                    source_dataset="endpoint_events",
                    event_id=str(event["event_id"]),
                    description="Suspicious PowerShell or process execution detected.",
                    mitre_tactic=rule["mitre_tactic"],
                    mitre_technique=rule["mitre_technique"],
                    recommended_action=(
                        "Inspect command line, parent process, and endpoint timeline."
                    ),
                    evidence={
                        "event_type": event_type,
                        "process_name": str(event.get("process_name")),
                        "severity": severity,
                    },
                )
            )
    return findings


def detect_malware(
    endpoint_events: pd.DataFrame,
    security_alerts: pd.DataFrame,
    rule: dict[str, Any],
    detection_timestamp: str,
) -> list[dict[str, Any]]:
    """Detect malware events from endpoint telemetry and alert records."""
    findings = []
    for _, event in endpoint_events.iterrows():
        if str(event.get("event_type", "")).lower() == "malware_detected":
            findings.append(
                build_finding(
                    detection_timestamp=detection_timestamp,
                    rule_id=rule["rule_id"],
                    rule_name=rule["rule_name"],
                    severity=str(event.get("severity", rule["severity"])).lower(),
                    confidence=0.95,
                    entity_type="device",
                    entity_id=str(event["device_id"]),
                    user_id=str(event.get("user_id")),
                    source_dataset="endpoint_events",
                    event_id=str(event["event_id"]),
                    description="Malware detection reported by endpoint telemetry.",
                    mitre_tactic=rule["mitre_tactic"],
                    mitre_technique=rule["mitre_technique"],
                    recommended_action="Isolate host and review malware remediation status.",
                    evidence={
                        "event_type": str(event.get("event_type")),
                        "hostname": str(event.get("hostname")),
                    },
                )
            )

    for _, alert in security_alerts.iterrows():
        if str(alert.get("alert_name", "")).lower() == "malware_detected":
            findings.append(
                build_finding(
                    detection_timestamp=detection_timestamp,
                    rule_id=rule["rule_id"],
                    rule_name=rule["rule_name"],
                    severity=str(alert.get("severity", rule["severity"])).lower(),
                    confidence=0.9,
                    entity_type=str(alert.get("entity_type", "device")),
                    entity_id=str(alert.get("entity_id")),
                    user_id=str(alert.get("user_id")),
                    source_dataset="security_alerts",
                    event_id=str(alert["alert_id"]),
                    description="Malware detection reported by security alert telemetry.",
                    mitre_tactic=rule["mitre_tactic"],
                    mitre_technique=rule["mitre_technique"],
                    recommended_action=(
                        "Triage alert, confirm containment, and collect endpoint evidence."
                    ),
                    evidence={
                        "alert_name": str(alert.get("alert_name")),
                        "status": str(alert.get("status")),
                    },
                )
            )
    return findings


def detect_suspicious_cloud_change(
    cloud_activity: pd.DataFrame,
    rule: dict[str, Any],
    detection_timestamp: str,
) -> list[dict[str, Any]]:
    """Detect risky cloud control-plane operations."""
    if cloud_activity.empty:
        return []

    findings = []
    for _, event in cloud_activity.iterrows():
        operation = str(event.get("operation_name", "")).lower()
        severity = str(event.get("severity", "")).lower()
        risk_hint = str(event.get("risk_hint", "")).lower()
        if operation in SUSPICIOUS_CLOUD_OPERATIONS and (
            severity in HIGH_RISK_VALUES or risk_hint in HIGH_RISK_VALUES
        ):
            findings.append(
                build_finding(
                    detection_timestamp=detection_timestamp,
                    rule_id=rule["rule_id"],
                    rule_name=rule["rule_name"],
                    severity=severity if severity in HIGH_RISK_VALUES else rule["severity"],
                    confidence=0.85,
                    entity_type="resource",
                    entity_id=str(event["resource_name"]),
                    user_id=None,
                    source_dataset="cloud_activity",
                    event_id=str(event["event_id"]),
                    description=f"Suspicious cloud control-plane operation: {operation}.",
                    mitre_tactic=rule["mitre_tactic"],
                    mitre_technique=rule["mitre_technique"],
                    recommended_action=(
                        "Review change authorization and restore secure configuration."
                    ),
                    evidence={
                        "operation_name": operation,
                        "caller": str(event.get("caller")),
                        "resource_type": str(event.get("resource_type")),
                        "severity": severity,
                        "risk_hint": risk_hint,
                    },
                )
            )
    return findings


def detect_bulk_application_export(
    application_events: pd.DataFrame,
    rule: dict[str, Any],
    detection_timestamp: str,
) -> list[dict[str, Any]]:
    """Detect bulk export or high-severity file download events."""
    if application_events.empty:
        return []

    findings = []
    for _, event in application_events.iterrows():
        event_type = str(event.get("event_type", "")).lower()
        severity = str(event.get("severity", "")).lower()
        is_bulk_export = event_type == "bulk_export"
        is_risky_download = event_type == "file_download" and severity in HIGH_RISK_VALUES
        if is_bulk_export or is_risky_download:
            findings.append(
                build_finding(
                    detection_timestamp=detection_timestamp,
                    rule_id=rule["rule_id"],
                    rule_name=rule["rule_name"],
                    severity=severity if severity in HIGH_RISK_VALUES else rule["severity"],
                    confidence=0.75,
                    entity_type="user",
                    entity_id=str(event["user_id"]),
                    user_id=str(event["user_id"]),
                    source_dataset="application_events",
                    event_id=str(event["event_id"]),
                    description="Bulk application export or risky file download detected.",
                    mitre_tactic=rule["mitre_tactic"],
                    mitre_technique=rule["mitre_technique"],
                    recommended_action="Review business justification and data access scope.",
                    evidence={
                        "application_name": str(event.get("application_name")),
                        "event_type": event_type,
                        "resource": str(event.get("resource")),
                        "severity": severity,
                    },
                )
            )
    return findings
