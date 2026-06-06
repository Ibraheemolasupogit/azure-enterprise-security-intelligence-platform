"""Synthetic telemetry generator for local security analytics development."""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from security_intelligence.telemetry.scenarios import (
    ALERT_TYPES,
    APPLICATION_EVENT_TYPES,
    CLOUD_OPERATIONS,
    ENDPOINT_EVENT_TYPES,
    IDENTITY_EVENT_TYPES,
)
from security_intelligence.telemetry.schemas import DATASET_FILENAMES

SYNTHETIC_END_TIME = datetime(2026, 1, 31, 12, 0, tzinfo=UTC)

DEPARTMENTS = ["Security", "Engineering", "Finance", "HR", "Sales", "Operations", "Legal"]
ROLES = ["User", "Security Reader", "Security Operator", "Application Admin", "Global Admin"]
COUNTRIES = [
    ("United States", "Seattle", "203.0.113."),
    ("United Kingdom", "London", "198.51.100."),
    ("Germany", "Berlin", "192.0.2."),
    ("Singapore", "Singapore", "203.0.114."),
    ("Australia", "Sydney", "198.51.101."),
]
APPLICATIONS = ["Microsoft 365", "Salesforce", "ServiceNow", "GitHub Enterprise", "Workday"]
HOST_PREFIXES = ["LAP", "WKS", "SRV"]
PROCESS_NAMES = [
    "outlook.exe",
    "teams.exe",
    "powershell.exe",
    "cmd.exe",
    "python.exe",
    "rundll32.exe",
]
RESOURCE_GROUPS = ["rg-security-prod", "rg-shared-services", "rg-data-platform", "rg-identity"]
RESOURCE_TYPES = [
    "Microsoft.KeyVault/vaults",
    "Microsoft.Storage/storageAccounts",
    "Microsoft.Compute/virtualMachines",
    "Microsoft.Network/networkSecurityGroups",
    "Microsoft.Authorization/roleAssignments",
    "Microsoft.Insights/diagnosticSettings",
]


@dataclass(frozen=True)
class SyntheticUser:
    """A deterministic synthetic identity used across generated datasets."""

    user_id: str
    user_principal_name: str
    department: str
    role: str
    location: str
    device_id: str
    hostname: str


def generate_telemetry(
    output_dir: str | Path,
    days: int = 30,
    seed: int = 42,
    users: int = 50,
) -> dict[str, int]:
    """Generate all synthetic telemetry JSONL datasets.

    Args:
        output_dir: Directory where JSONL files will be written.
        days: Number of synthetic days covered by generated timestamps.
        seed: Random seed used for deterministic generation.
        users: Number of synthetic users to create.

    Returns:
        Record counts keyed by dataset name.
    """
    if days < 1:
        raise ValueError("days must be at least 1")
    if users < 4:
        raise ValueError("users must be at least 4 to create linked scenarios")

    rng = random.Random(seed)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    synthetic_users = _build_users(rng, users)
    datasets = {
        "identity_events": _generate_identity_events(rng, synthetic_users, days),
        "login_events": _generate_login_events(rng, synthetic_users, days),
        "endpoint_events": _generate_endpoint_events(rng, synthetic_users, days),
        "application_events": _generate_application_events(rng, synthetic_users, days),
        "security_alerts": [],
        "cloud_activity": _generate_cloud_activity(rng, synthetic_users, days),
    }

    _add_linked_scenarios(rng, datasets, synthetic_users, days)

    counts = {}
    for dataset_name, records in datasets.items():
        records.sort(key=lambda record: record["timestamp"])
        _write_jsonl(output_path / DATASET_FILENAMES[dataset_name], records)
        counts[dataset_name] = len(records)

    return counts


def _build_users(rng: random.Random, user_count: int) -> list[SyntheticUser]:
    first_names = [
        "alex",
        "jordan",
        "taylor",
        "casey",
        "morgan",
        "riley",
        "jamie",
        "avery",
        "sam",
        "quinn",
    ]
    last_names = [
        "chen",
        "patel",
        "roberts",
        "nguyen",
        "garcia",
        "smith",
        "brown",
        "wilson",
        "khan",
        "evans",
    ]

    synthetic_users = []
    for index in range(user_count):
        first = first_names[index % len(first_names)]
        last = last_names[(index // len(first_names)) % len(last_names)]
        suffix = f"{index + 1:03d}"
        role = "Global Admin" if index in {0, 1} else rng.choice(ROLES[:-1])
        device_id = f"dev-{index + 1:04d}"
        synthetic_users.append(
            SyntheticUser(
                user_id=f"user-{index + 1:04d}",
                user_principal_name=f"{first}.{last}{suffix}@contoso.example",
                department=rng.choice(DEPARTMENTS),
                role=role,
                location=rng.choice([city for _, city, _ in COUNTRIES]),
                device_id=device_id,
                hostname=f"{rng.choice(HOST_PREFIXES)}-{suffix}",
            )
        )
    return synthetic_users


def _timestamp(rng: random.Random, days: int, offset_minutes: int = 0) -> str:
    start = SYNTHETIC_END_TIME - timedelta(days=days)
    total_minutes = days * 24 * 60
    event_time = start + timedelta(minutes=rng.randrange(total_minutes) + offset_minutes)
    return event_time.isoformat()


def _event_id(prefix: str, index: int) -> str:
    return f"{prefix}-{index:06d}"


def _location(rng: random.Random) -> tuple[str, str, str]:
    country, city, prefix = rng.choice(COUNTRIES)
    return country, city, f"{prefix}{rng.randint(10, 240)}"


def _risk_for_event(event_type: str) -> str:
    if event_type in {
        "mfa_disabled",
        "privileged_role_activated",
        "suspicious_process",
        "powershell_execution",
        "privilege_escalation_attempt",
        "bulk_export",
        "api_token_created",
        "diagnostic_setting_disabled",
    }:
        return "elevated"
    if event_type in {"malware_detected", "device_isolated", "role_assignment_created"}:
        return "high"
    return "normal"


def _generate_identity_events(
    rng: random.Random, synthetic_users: list[SyntheticUser], days: int
) -> list[dict[str, Any]]:
    records = []
    for index, user in enumerate(synthetic_users, start=1):
        event_type = rng.choice(IDENTITY_EVENT_TYPES)
        records.append(
            {
                "event_id": _event_id("id", index),
                "timestamp": _timestamp(rng, days),
                "user_id": user.user_id,
                "user_principal_name": user.user_principal_name,
                "department": user.department,
                "role": user.role,
                "event_type": event_type,
                "source_system": "Microsoft Entra ID",
                "risk_hint": _risk_for_event(event_type),
                "location": user.location,
                "metadata": {
                    "correlation_id": _event_id("corr-id", index),
                    "actor": "identity-automation@contoso.example",
                },
            }
        )
    return records


def _generate_login_events(
    rng: random.Random, synthetic_users: list[SyntheticUser], days: int
) -> list[dict[str, Any]]:
    records = []
    index = 1
    auth_methods = ["mfa_push", "passwordless", "fido2", "password", "legacy_basic"]
    for user in synthetic_users:
        for _ in range(rng.randint(2, 4)):
            country, city, ip_address = _location(rng)
            failed = rng.random() < 0.18
            legacy = rng.random() < 0.05
            auth_method = "legacy_basic" if legacy else rng.choice(auth_methods[:-1])
            records.append(
                {
                    "event_id": _event_id("login", index),
                    "timestamp": _timestamp(rng, days),
                    "user_id": user.user_id,
                    "user_principal_name": user.user_principal_name,
                    "ip_address": ip_address,
                    "country": country,
                    "city": city,
                    "device_id": user.device_id,
                    "auth_method": auth_method,
                    "login_status": "failure" if failed else "success",
                    "failure_reason": rng.choice(["invalid_password", "mfa_denied"])
                    if failed
                    else None,
                    "risk_hint": "elevated" if failed or legacy else "normal",
                    "metadata": {
                        "user_agent": rng.choice(["Edge", "Chrome", "Mobile Outlook", "Azure CLI"]),
                        "pattern": "legacy_authentication_attempt" if legacy else "baseline",
                    },
                }
            )
            index += 1
    return records


def _generate_endpoint_events(
    rng: random.Random, synthetic_users: list[SyntheticUser], days: int
) -> list[dict[str, Any]]:
    records = []
    for index in range(max(20, len(synthetic_users)), max(20, len(synthetic_users)) * 2):
        user = rng.choice(synthetic_users)
        event_type = rng.choice(ENDPOINT_EVENT_TYPES)
        process_name = (
            "powershell.exe" if event_type == "powershell_execution" else rng.choice(PROCESS_NAMES)
        )
        records.append(
            {
                "event_id": _event_id("endpoint", index),
                "timestamp": _timestamp(rng, days),
                "device_id": user.device_id,
                "hostname": user.hostname,
                "user_id": user.user_id,
                "process_name": process_name,
                "event_type": event_type,
                "severity": _severity_for_event(event_type),
                "risk_hint": _risk_for_event(event_type),
                "metadata": {
                    "command_line": _command_line_for(process_name, event_type),
                    "sensor": "Microsoft Defender for Endpoint",
                },
            }
        )
    return records


def _generate_application_events(
    rng: random.Random, synthetic_users: list[SyntheticUser], days: int
) -> list[dict[str, Any]]:
    records = []
    for index in range(max(25, len(synthetic_users) + 5)):
        user = rng.choice(synthetic_users)
        event_type = rng.choice(APPLICATION_EVENT_TYPES)
        records.append(
            {
                "event_id": _event_id("app", index + 1),
                "timestamp": _timestamp(rng, days),
                "application_name": rng.choice(APPLICATIONS),
                "user_id": user.user_id,
                "user_principal_name": user.user_principal_name,
                "event_type": event_type,
                "resource": rng.choice(["customer-data", "payroll", "source-repo", "ticket-queue"]),
                "action": event_type,
                "severity": _severity_for_event(event_type),
                "risk_hint": _risk_for_event(event_type),
                "metadata": {
                    "session_id": _event_id("sess", index + 1),
                    "records_affected": (
                        rng.randint(1, 5000) if event_type == "bulk_export" else None
                    ),
                },
            }
        )
    return records


def _generate_cloud_activity(
    rng: random.Random, synthetic_users: list[SyntheticUser], days: int
) -> list[dict[str, Any]]:
    records = []
    for index in range(max(20, len(synthetic_users))):
        user = rng.choice(synthetic_users)
        operation = rng.choice(CLOUD_OPERATIONS)
        resource_type = RESOURCE_TYPES[CLOUD_OPERATIONS.index(operation)]
        records.append(
            {
                "event_id": _event_id("cloud", index + 1),
                "timestamp": _timestamp(rng, days),
                "subscription_id": "sub-prod-001",
                "resource_group": rng.choice(RESOURCE_GROUPS),
                "resource_type": resource_type,
                "resource_name": f"{resource_type.split('/')[-1].lower()}-{rng.randint(100, 999)}",
                "operation_name": operation,
                "caller": user.user_principal_name,
                "result": "success" if rng.random() > 0.08 else "failure",
                "severity": _severity_for_event(operation),
                "risk_hint": _risk_for_event(operation),
                "metadata": {
                    "client_ip": _location(rng)[2],
                    "correlation_id": _event_id("corr-cloud", index + 1),
                },
            }
        )
    return records


def _add_linked_scenarios(
    rng: random.Random,
    datasets: dict[str, list[dict[str, Any]]],
    synthetic_users: list[SyntheticUser],
    days: int,
) -> None:
    scenario_start = SYNTHETIC_END_TIME - timedelta(days=max(1, days // 3))

    impossible_user = synthetic_users[0]
    first_login_time = scenario_start
    second_login_time = first_login_time + timedelta(minutes=45)
    datasets["login_events"].extend(
        [
            _login_record(
                "login-scenario-000001",
                first_login_time,
                impossible_user,
                "United States",
                "Seattle",
                "203.0.113.25",
                "success",
                "normal",
                {"pattern": "impossible_travel_start"},
            ),
            _login_record(
                "login-scenario-000002",
                second_login_time,
                impossible_user,
                "Germany",
                "Berlin",
                "192.0.2.44",
                "success",
                "high",
                {"pattern": "impossible_travel"},
            ),
        ]
    )
    datasets["security_alerts"].append(
        _alert_record(
            "alert-000001",
            second_login_time + timedelta(minutes=3),
            "impossible_travel",
            "user",
            impossible_user.user_id,
            impossible_user.user_id,
            "Synthetic impossible travel pattern detected across two successful logins.",
            {"linked_events": ["login-scenario-000001", "login-scenario-000002"]},
        )
    )

    privileged_user = synthetic_users[1]
    role_time = scenario_start + timedelta(days=2)
    datasets["identity_events"].append(
        {
            "event_id": "id-scenario-000001",
            "timestamp": role_time.isoformat(),
            "user_id": privileged_user.user_id,
            "user_principal_name": privileged_user.user_principal_name,
            "department": privileged_user.department,
            "role": "Global Admin",
            "event_type": "role_assigned",
            "source_system": "Microsoft Entra ID",
            "risk_hint": "elevated",
            "location": privileged_user.location,
            "metadata": {"scenario": "privileged_role_assignment"},
        }
    )
    cloud_time = role_time + timedelta(minutes=20)
    datasets["cloud_activity"].append(
        {
            "event_id": "cloud-scenario-000001",
            "timestamp": cloud_time.isoformat(),
            "subscription_id": "sub-prod-001",
            "resource_group": "rg-security-prod",
            "resource_type": "Microsoft.Insights/diagnosticSettings",
            "resource_name": "diagnosticsettings-prod",
            "operation_name": "diagnostic_setting_disabled",
            "caller": privileged_user.user_principal_name,
            "result": "success",
            "severity": "high",
            "risk_hint": "high",
            "metadata": {"linked_identity_event": "id-scenario-000001"},
        }
    )
    datasets["security_alerts"].append(
        _alert_record(
            "alert-000002",
            cloud_time + timedelta(minutes=2),
            "privilege_escalation",
            "user",
            privileged_user.user_id,
            privileged_user.user_id,
            "Privileged role assignment followed by sensitive cloud control-plane activity.",
            {"linked_events": ["id-scenario-000001", "cloud-scenario-000001"]},
        )
    )

    malware_user = synthetic_users[2]
    malware_time = scenario_start + timedelta(days=4, minutes=rng.randint(1, 90))
    datasets["endpoint_events"].append(
        {
            "event_id": "endpoint-scenario-000001",
            "timestamp": malware_time.isoformat(),
            "device_id": malware_user.device_id,
            "hostname": malware_user.hostname,
            "user_id": malware_user.user_id,
            "process_name": "rundll32.exe",
            "event_type": "malware_detected",
            "severity": "critical",
            "risk_hint": "high",
            "metadata": {
                "malware_family": "SyntheticLoader",
                "sensor": "Microsoft Defender for Endpoint",
            },
        }
    )
    datasets["security_alerts"].append(
        _alert_record(
            "alert-000003",
            malware_time + timedelta(minutes=1),
            "malware_detected",
            "device",
            malware_user.device_id,
            malware_user.user_id,
            "Synthetic malware detection on a managed endpoint.",
            {"linked_events": ["endpoint-scenario-000001"]},
        )
    )

    dormant_user = synthetic_users[3]
    dormant_time = SYNTHETIC_END_TIME - timedelta(days=days - 1)
    datasets["identity_events"].append(
        {
            "event_id": "id-scenario-000002",
            "timestamp": dormant_time.isoformat(),
            "user_id": dormant_user.user_id,
            "user_principal_name": dormant_user.user_principal_name,
            "department": dormant_user.department,
            "role": "Security Operator",
            "event_type": "privileged_role_activated",
            "source_system": "Microsoft Entra ID",
            "risk_hint": "elevated",
            "location": dormant_user.location,
            "metadata": {"scenario": "dormant_privileged_account"},
        }
    )
    datasets["security_alerts"].append(
        _alert_record(
            "alert-000004",
            SYNTHETIC_END_TIME - timedelta(hours=12),
            "dormant_privileged_account",
            "user",
            dormant_user.user_id,
            dormant_user.user_id,
            "Privileged account has historical activation with no recent login activity.",
            {"linked_events": ["id-scenario-000002"]},
        )
    )

    lateral_user = rng.choice(synthetic_users)
    lateral_time = scenario_start + timedelta(days=6, minutes=15)
    datasets["security_alerts"].append(
        _alert_record(
            "alert-000005",
            lateral_time,
            "lateral_movement",
            "device",
            lateral_user.device_id,
            lateral_user.user_id,
            "Synthetic lateral movement pattern across managed endpoint activity.",
            {"source": "scenario_seed"},
        )
    )
    datasets["security_alerts"].append(
        _alert_record(
            "alert-000006",
            lateral_time + timedelta(hours=3),
            "suspicious_login",
            "user",
            lateral_user.user_id,
            lateral_user.user_id,
            "Synthetic suspicious login from unfamiliar context.",
            {"source": "scenario_seed"},
        )
    )


def _login_record(
    event_id: str,
    timestamp: datetime,
    user: SyntheticUser,
    country: str,
    city: str,
    ip_address: str,
    status: str,
    risk_hint: str,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    return {
        "event_id": event_id,
        "timestamp": timestamp.isoformat(),
        "user_id": user.user_id,
        "user_principal_name": user.user_principal_name,
        "ip_address": ip_address,
        "country": country,
        "city": city,
        "device_id": user.device_id,
        "auth_method": "mfa_push",
        "login_status": status,
        "failure_reason": None,
        "risk_hint": risk_hint,
        "metadata": metadata,
    }


def _alert_record(
    alert_id: str,
    timestamp: datetime,
    alert_name: str,
    entity_type: str,
    entity_id: str,
    user_id: str,
    description: str,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    alert_details = ALERT_TYPES[alert_name]
    return {
        "alert_id": alert_id,
        "timestamp": timestamp.isoformat(),
        "alert_name": alert_name,
        "severity": alert_details["severity"],
        "entity_type": entity_type,
        "entity_id": entity_id,
        "user_id": user_id,
        "description": description,
        "mitre_tactic": alert_details["mitre_tactic"],
        "mitre_technique": alert_details["mitre_technique"],
        "status": "new",
        "risk_hint": "high" if alert_details["severity"] in {"high", "critical"} else "elevated",
        "metadata": metadata,
    }


def _severity_for_event(event_type: str) -> str:
    if event_type in {"malware_detected", "diagnostic_setting_disabled"}:
        return "critical"
    if event_type in {
        "suspicious_process",
        "device_isolated",
        "privilege_escalation_attempt",
        "bulk_export",
        "admin_setting_changed",
        "api_token_created",
        "role_assignment_created",
    }:
        return "high"
    if event_type in {"powershell_execution", "network_rule_changed", "storage_blob_downloaded"}:
        return "medium"
    return "low"


def _command_line_for(process_name: str, event_type: str) -> str:
    if event_type == "powershell_execution":
        return "powershell.exe -NoProfile Get-Process"
    if event_type == "privilege_escalation_attempt":
        return f"{process_name} --attempt-elevated-token"
    return process_name


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as file:
        for record in records:
            file.write(json.dumps(record, sort_keys=True) + "\n")
