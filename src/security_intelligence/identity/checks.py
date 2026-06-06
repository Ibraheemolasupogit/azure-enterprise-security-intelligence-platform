"""Deterministic identity governance checks."""

from __future__ import annotations

from typing import Any

import pandas as pd

from security_intelligence.identity.models import build_governance_finding

DEFAULT_PRIVILEGED_ROLES = {
    "global administrator",
    "global admin",
    "security administrator",
    "security operator",
    "privileged role administrator",
    "owner",
    "contributor",
    "user access administrator",
}
DEFAULT_RISKY_RISK_HINTS = {"medium", "high", "critical", "elevated"}
HIGH_RISK_CLOUD_OPERATIONS = {
    "diagnostic_setting_disabled",
    "network_rule_changed",
    "role_assignment_created",
    "key_vault_secret_accessed",
}


def build_identity_profiles(identity_events: pd.DataFrame) -> dict[str, dict[str, Any]]:
    """Create user profiles from identity telemetry."""
    profiles: dict[str, dict[str, Any]] = {}
    if identity_events.empty:
        return profiles

    sorted_events = identity_events.sort_values("timestamp")
    guest_user_ids = set(
        sorted_events.loc[
            sorted_events["event_type"].astype(str).str.lower() == "guest_invited",
            "user_id",
        ].astype(str)
    )

    for user_id, events in sorted_events.groupby("user_id"):
        latest = events.iloc[-1]
        profiles[str(user_id)] = {
            "user_id": str(user_id),
            "user_principal_name": str(latest.get("user_principal_name", "")),
            "department": str(latest.get("department", "")),
            "role": str(latest.get("role", "")),
            "identity_type": "Guest" if str(user_id) in guest_user_ids else "Member",
        }
    return profiles


def check_dormant_users(
    identity_events: pd.DataFrame,
    login_events: pd.DataFrame,
    *,
    check_timestamp: str,
    reference_time: pd.Timestamp,
    inactivity_days: int,
) -> list[dict[str, Any]]:
    """Identify users with no successful login inside the inactivity window."""
    profiles = build_identity_profiles(identity_events)
    last_success = _last_successful_login(login_events)
    cutoff = reference_time - pd.Timedelta(days=inactivity_days)
    findings = []

    for user_id, profile in profiles.items():
        last_login = last_success.get(user_id)
        if last_login is None or last_login < cutoff:
            findings.append(
                _finding(
                    profile,
                    check_timestamp,
                    "IDG-001",
                    "Dormant user",
                    "medium",
                    "dormant_user",
                    "User has no successful login activity inside the inactivity window.",
                    "Confirm whether the account is still required or disable it.",
                    {
                        "last_successful_login": _timestamp_or_none(last_login),
                        "inactivity_days": inactivity_days,
                        "reference_time": reference_time.isoformat(),
                    },
                    ["identity_events", "login_events"],
                )
            )
    return findings


def check_dormant_privileged_accounts(
    identity_events: pd.DataFrame,
    login_events: pd.DataFrame,
    *,
    check_timestamp: str,
    reference_time: pd.Timestamp,
    inactivity_days: int,
    privileged_roles: set[str],
) -> list[dict[str, Any]]:
    """Identify privileged users with no recent successful login activity."""
    profiles = build_identity_profiles(identity_events)
    last_success = _last_successful_login(login_events)
    cutoff = reference_time - pd.Timedelta(days=inactivity_days)
    findings = []

    for user_id, profile in profiles.items():
        if not _is_privileged_role(profile["role"], privileged_roles):
            continue
        last_login = last_success.get(user_id)
        if last_login is None or last_login < cutoff:
            findings.append(
                _finding(
                    profile,
                    check_timestamp,
                    "IDG-002",
                    "Dormant privileged account",
                    "high",
                    "dormant_privileged_account",
                    "Privileged account has no successful login inside the inactivity window.",
                    "Review privileged access, remove stale assignments, or disable the account.",
                    {
                        "last_successful_login": _timestamp_or_none(last_login),
                        "inactivity_days": inactivity_days,
                        "role": profile["role"],
                    },
                    ["identity_events", "login_events"],
                )
            )
    return findings


def check_mfa_disabled_or_missing(
    identity_events: pd.DataFrame,
    *,
    check_timestamp: str,
) -> list[dict[str, Any]]:
    """Identify users with MFA disabled or without a clear MFA enabled signal."""
    profiles = build_identity_profiles(identity_events)
    mfa_enabled = set(
        identity_events.loc[
            identity_events["event_type"].astype(str).str.lower() == "mfa_enabled",
            "user_id",
        ].astype(str)
    )
    mfa_disabled_events = identity_events[
        identity_events["event_type"].astype(str).str.lower() == "mfa_disabled"
    ]
    findings = []

    for _, event in mfa_disabled_events.iterrows():
        profile = profiles.get(str(event["user_id"]), _profile_from_event(event))
        findings.append(
            _finding(
                profile,
                check_timestamp,
                "IDG-003",
                "MFA disabled or missing",
                "high",
                "mfa_gap",
                "User has an MFA disabled event.",
                "Re-enable MFA and review conditional access coverage.",
                {"event_id": str(event.get("event_id")), "event_type": "mfa_disabled"},
                ["identity_events"],
            )
        )

    users_with_findings = {finding["user_id"] for finding in findings}
    for user_id, profile in profiles.items():
        if user_id not in mfa_enabled and user_id not in users_with_findings:
            findings.append(
                _finding(
                    profile,
                    check_timestamp,
                    "IDG-003",
                    "MFA disabled or missing",
                    "medium",
                    "mfa_gap",
                    "User has no clear MFA enabled signal in synthetic identity telemetry.",
                    "Verify MFA registration and enforce strong authentication.",
                    {"mfa_enabled_signal_present": False},
                    ["identity_events"],
                )
            )
    return findings


def check_guest_user_exposure(
    identity_events: pd.DataFrame,
    application_events: pd.DataFrame,
    cloud_activity: pd.DataFrame,
    *,
    check_timestamp: str,
    privileged_roles: set[str],
) -> list[dict[str, Any]]:
    """Identify guest users and flag sensitive guest exposure."""
    profiles = build_identity_profiles(identity_events)
    guest_events = identity_events[
        identity_events["event_type"].astype(str).str.lower() == "guest_invited"
    ]
    findings = []

    for _, event in guest_events.iterrows():
        profile = profiles.get(
            str(event["user_id"]),
            _profile_from_event(event, identity_type="Guest"),
        )
        sensitive_app_events = application_events[
            application_events["user_id"].astype(str) == profile["user_id"]
        ]
        sensitive_cloud_events = cloud_activity[
            cloud_activity["caller"].astype(str) == profile["user_principal_name"]
        ]
        privileged = _is_privileged_role(profile["role"], privileged_roles)
        sensitive_activity = not sensitive_app_events.empty or not sensitive_cloud_events.empty
        severity = "high" if privileged or sensitive_activity else "medium"
        findings.append(
            _finding(
                profile,
                check_timestamp,
                "IDG-004",
                "Guest user exposure",
                severity,
                "guest_exposure",
                "Guest identity is present in identity telemetry.",
                "Review guest access, ownership, expiration, and application permissions.",
                {
                    "event_id": str(event.get("event_id")),
                    "privileged_role": privileged,
                    "application_event_count": int(len(sensitive_app_events)),
                    "cloud_activity_count": int(len(sensitive_cloud_events)),
                },
                ["identity_events", "application_events", "cloud_activity"],
            )
        )
    return findings


def check_role_sprawl(
    identity_events: pd.DataFrame,
    *,
    check_timestamp: str,
    threshold: int,
) -> list[dict[str, Any]]:
    """Identify users with repeated role assignment or activation events."""
    profiles = build_identity_profiles(identity_events)
    role_events = identity_events[
        identity_events["event_type"].astype(str).str.lower().isin(
            {"role_assigned", "privileged_role_activated"}
        )
    ]
    findings = []

    for user_id, events in role_events.groupby("user_id"):
        if len(events) >= threshold:
            profile = profiles.get(str(user_id), _profile_from_event(events.iloc[-1]))
            findings.append(
                _finding(
                    profile,
                    check_timestamp,
                    "IDG-005",
                    "Role sprawl",
                    "medium",
                    "role_sprawl",
                    "User has multiple role assignment or activation events.",
                    "Review role necessity and consolidate least-privilege access.",
                    {
                        "role_event_count": int(len(events)),
                        "threshold": threshold,
                        "event_ids": [str(value) for value in events["event_id"].tolist()],
                    },
                    ["identity_events"],
                )
            )
    return findings


def check_risky_privilege_assignment(
    identity_events: pd.DataFrame,
    *,
    check_timestamp: str,
    privileged_roles: set[str],
    risky_risk_hints: set[str],
) -> list[dict[str, Any]]:
    """Identify risky privileged role assignment or activation events."""
    profiles = build_identity_profiles(identity_events)
    role_events = identity_events[
        identity_events["event_type"].astype(str).str.lower().isin(
            {"role_assigned", "privileged_role_activated"}
        )
    ]
    findings = []

    for _, event in role_events.iterrows():
        role = str(event.get("role", ""))
        risk_hint = str(event.get("risk_hint", "")).lower()
        if _is_privileged_role(role, privileged_roles) and risk_hint in risky_risk_hints:
            profile = profiles.get(str(event["user_id"]), _profile_from_event(event))
            findings.append(
                _finding(
                    profile,
                    check_timestamp,
                    "IDG-006",
                    "Risky privilege assignment",
                    "high",
                    "risky_privilege_assignment",
                    "Privileged role event has an elevated risk hint.",
                    "Validate approval, justification, and time-bound access controls.",
                    {
                        "event_id": str(event.get("event_id")),
                        "event_type": str(event.get("event_type")),
                        "role": role,
                        "risk_hint": risk_hint,
                    },
                    ["identity_events"],
                )
            )
    return findings


def check_privileged_cloud_activity(
    identity_events: pd.DataFrame,
    cloud_activity: pd.DataFrame,
    *,
    check_timestamp: str,
    privileged_roles: set[str],
) -> list[dict[str, Any]]:
    """Identify high-risk cloud activity performed by privileged users."""
    profiles = build_identity_profiles(identity_events)
    profiles_by_upn = {profile["user_principal_name"]: profile for profile in profiles.values()}
    findings = []

    for _, event in cloud_activity.iterrows():
        caller = str(event.get("caller", ""))
        profile = profiles_by_upn.get(caller)
        if profile is None:
            continue
        operation = str(event.get("operation_name", "")).lower()
        severity = str(event.get("severity", "")).lower()
        risk_hint = str(event.get("risk_hint", "")).lower()
        if _is_privileged_role(profile["role"], privileged_roles) and (
            operation in HIGH_RISK_CLOUD_OPERATIONS
            or severity in {"high", "critical"}
            or risk_hint in {"high", "critical", "elevated"}
        ):
            findings.append(
                _finding(
                    profile,
                    check_timestamp,
                    "IDG-007",
                    "Privileged cloud activity",
                    "high" if severity != "critical" else "critical",
                    "privileged_cloud_activity",
                    "Privileged user performed high-risk cloud control-plane activity.",
                    "Review change ticket, resource scope, and privileged session evidence.",
                    {
                        "event_id": str(event.get("event_id")),
                        "operation_name": operation,
                        "resource_name": str(event.get("resource_name")),
                        "severity": severity,
                        "risk_hint": risk_hint,
                    },
                    ["identity_events", "cloud_activity"],
                )
            )
    return findings


def _last_successful_login(login_events: pd.DataFrame) -> dict[str, pd.Timestamp]:
    if login_events.empty:
        return {}
    dataframe = login_events.copy()
    dataframe["parsed_timestamp"] = pd.to_datetime(dataframe["timestamp"], errors="coerce")
    successful = dataframe[
        (dataframe["login_status"].astype(str).str.lower() == "success")
        & dataframe["parsed_timestamp"].notna()
    ]
    return {
        str(user_id): timestamp
        for user_id, timestamp in successful.groupby("user_id")["parsed_timestamp"].max().items()
    }


def _finding(
    profile: dict[str, Any],
    check_timestamp: str,
    check_id: str,
    check_name: str,
    severity: str,
    finding_category: str,
    description: str,
    recommended_action: str,
    evidence: dict[str, Any],
    source_datasets: list[str],
) -> dict[str, Any]:
    return build_governance_finding(
        check_timestamp=check_timestamp,
        check_id=check_id,
        check_name=check_name,
        severity=severity,
        user_id=profile["user_id"],
        user_principal_name=profile["user_principal_name"],
        identity_type=profile["identity_type"],
        department=profile["department"],
        role=profile["role"],
        finding_category=finding_category,
        description=description,
        recommended_action=recommended_action,
        evidence=evidence,
        source_datasets=source_datasets,
    )


def _profile_from_event(event: pd.Series, identity_type: str = "Member") -> dict[str, str]:
    return {
        "user_id": str(event.get("user_id", "")),
        "user_principal_name": str(event.get("user_principal_name", "")),
        "department": str(event.get("department", "")),
        "role": str(event.get("role", "")),
        "identity_type": identity_type,
    }


def _is_privileged_role(role: str, privileged_roles: set[str]) -> bool:
    normalized = role.lower().replace("administrator", "admin")
    normalized_roles = {
        value.lower().replace("administrator", "admin") for value in privileged_roles
    }
    return normalized in normalized_roles


def _timestamp_or_none(timestamp: pd.Timestamp | None) -> str | None:
    if timestamp is None:
        return None
    return timestamp.isoformat()
