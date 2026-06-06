import pandas as pd

from security_intelligence.detections.rules import (
    detect_bulk_application_export,
    detect_impossible_travel,
    detect_malware,
    detect_privileged_role_activation,
    detect_repeated_failed_login,
    detect_suspicious_cloud_change,
    detect_suspicious_powershell,
)

TIMESTAMP = "2026-06-06T12:00:00+00:00"


def _rule(rule_id: str, name: str, severity: str = "high") -> dict:
    return {
        "rule_id": rule_id,
        "rule_name": name,
        "severity": severity,
        "mitre_tactic": "Test Tactic",
        "mitre_technique": "Test Technique",
        "window_minutes": 120,
        "threshold": 3,
    }


def test_detect_impossible_travel_returns_expected_finding() -> None:
    dataframe = pd.DataFrame(
        [
            {
                "event_id": "login-1",
                "timestamp": "2026-01-01T10:00:00+00:00",
                "user_id": "user-1",
                "login_status": "success",
                "country": "United States",
            },
            {
                "event_id": "login-2",
                "timestamp": "2026-01-01T10:45:00+00:00",
                "user_id": "user-1",
                "login_status": "success",
                "country": "Germany",
            },
        ]
    )

    findings = detect_impossible_travel(dataframe, _rule("DET-001", "Impossible travel"), TIMESTAMP)

    assert len(findings) == 1
    assert findings[0]["mitre_tactic"] == "Test Tactic"
    assert findings[0]["evidence"]["previous_event_id"] == "login-1"


def test_detect_repeated_failed_login_returns_expected_finding() -> None:
    dataframe = pd.DataFrame(
        [
            {
                "event_id": f"login-{index}",
                "timestamp": f"2026-01-01T10:0{index}:00+00:00",
                "user_id": "user-1",
                "login_status": "failure",
            }
            for index in range(3)
        ]
    )

    findings = detect_repeated_failed_login(dataframe, _rule("DET-002", "Failed login"), TIMESTAMP)

    assert len(findings) == 1
    assert findings[0]["evidence"]["threshold"] == 3


def test_detect_privileged_role_activation_returns_expected_finding() -> None:
    dataframe = pd.DataFrame(
        [
            {
                "event_id": "id-1",
                "user_id": "user-1",
                "user_principal_name": "admin@example.test",
                "event_type": "role_assigned",
                "role": "Global Admin",
            }
        ]
    )

    findings = detect_privileged_role_activation(
        dataframe, _rule("DET-003", "Privileged role"), TIMESTAMP
    )

    assert len(findings) == 1
    assert findings[0]["evidence"]["role"] == "Global Admin"


def test_detect_suspicious_powershell_returns_expected_finding() -> None:
    dataframe = pd.DataFrame(
        [
            {
                "event_id": "endpoint-1",
                "device_id": "device-1",
                "user_id": "user-1",
                "event_type": "powershell_execution",
                "process_name": "powershell.exe",
                "severity": "high",
            }
        ]
    )

    findings = detect_suspicious_powershell(
        dataframe, _rule("DET-004", "PowerShell"), TIMESTAMP
    )

    assert len(findings) == 1
    assert findings[0]["entity_type"] == "device"


def test_detect_malware_returns_expected_findings() -> None:
    endpoint = pd.DataFrame(
        [
            {
                "event_id": "endpoint-1",
                "device_id": "device-1",
                "user_id": "user-1",
                "event_type": "malware_detected",
                "severity": "critical",
                "hostname": "host-1",
            }
        ]
    )
    alerts = pd.DataFrame(
        [
            {
                "alert_id": "alert-1",
                "alert_name": "malware_detected",
                "severity": "critical",
                "entity_type": "device",
                "entity_id": "device-1",
                "user_id": "user-1",
                "status": "new",
            }
        ]
    )

    findings = detect_malware(endpoint, alerts, _rule("DET-005", "Malware"), TIMESTAMP)

    assert len(findings) == 2
    assert all(finding["evidence"] for finding in findings)


def test_detect_suspicious_cloud_change_returns_expected_finding() -> None:
    dataframe = pd.DataFrame(
        [
            {
                "event_id": "cloud-1",
                "operation_name": "diagnostic_setting_disabled",
                "resource_name": "diagnostics",
                "resource_type": "Microsoft.Insights/diagnosticSettings",
                "caller": "admin@example.test",
                "severity": "high",
                "risk_hint": "high",
            }
        ]
    )

    findings = detect_suspicious_cloud_change(dataframe, _rule("DET-006", "Cloud"), TIMESTAMP)

    assert len(findings) == 1
    assert findings[0]["mitre_technique"] == "Test Technique"


def test_detect_bulk_application_export_returns_expected_finding() -> None:
    dataframe = pd.DataFrame(
        [
            {
                "event_id": "app-1",
                "application_name": "Microsoft 365",
                "user_id": "user-1",
                "event_type": "bulk_export",
                "resource": "customer-data",
                "severity": "medium",
            }
        ]
    )

    findings = detect_bulk_application_export(
        dataframe, _rule("DET-007", "Bulk export", "medium"), TIMESTAMP
    )

    assert len(findings) == 1
    assert findings[0]["mitre_tactic"] == "Test Tactic"

