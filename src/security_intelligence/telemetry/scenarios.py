"""Reusable scenario metadata for synthetic security telemetry."""

from __future__ import annotations

IDENTITY_EVENT_TYPES = [
    "user_created",
    "user_disabled",
    "role_assigned",
    "role_removed",
    "mfa_enabled",
    "mfa_disabled",
    "guest_invited",
    "privileged_role_activated",
]

LOGIN_PATTERNS = [
    "successful_login",
    "failed_login",
    "impossible_travel",
    "unfamiliar_location",
    "repeated_failed_login",
    "privileged_user_login",
    "legacy_authentication_attempt",
]

ENDPOINT_EVENT_TYPES = [
    "process_started",
    "suspicious_process",
    "malware_detected",
    "device_isolated",
    "powershell_execution",
    "privilege_escalation_attempt",
]

APPLICATION_EVENT_TYPES = [
    "app_login",
    "file_download",
    "bulk_export",
    "admin_setting_changed",
    "api_token_created",
    "permission_granted",
]

ALERT_TYPES = {
    "impossible_travel": {
        "severity": "high",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "Valid Accounts",
    },
    "suspicious_login": {
        "severity": "medium",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "Valid Accounts",
    },
    "privilege_escalation": {
        "severity": "high",
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "Account Manipulation",
    },
    "lateral_movement": {
        "severity": "high",
        "mitre_tactic": "Lateral Movement",
        "mitre_technique": "Remote Services",
    },
    "malware_detected": {
        "severity": "critical",
        "mitre_tactic": "Execution",
        "mitre_technique": "Malicious File",
    },
    "dormant_privileged_account": {
        "severity": "medium",
        "mitre_tactic": "Persistence",
        "mitre_technique": "Valid Accounts",
    },
}

CLOUD_OPERATIONS = [
    "key_vault_secret_accessed",
    "storage_blob_downloaded",
    "vm_created",
    "network_rule_changed",
    "role_assignment_created",
    "diagnostic_setting_disabled",
]

