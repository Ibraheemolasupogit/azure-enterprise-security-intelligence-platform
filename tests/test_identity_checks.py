import pandas as pd

from security_intelligence.identity.checks import (
    check_dormant_privileged_accounts,
    check_dormant_users,
    check_guest_user_exposure,
    check_mfa_disabled_or_missing,
    check_privileged_cloud_activity,
    check_risky_privilege_assignment,
    check_role_sprawl,
)

TIMESTAMP = "2026-06-06T12:00:00+00:00"
REFERENCE_TIME = pd.Timestamp("2026-01-31T12:00:00+00:00")
PRIVILEGED_ROLES = {"global admin", "security operator"}


def _identity_events() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "event_id": "id-1",
                "timestamp": "2026-01-01T00:00:00+00:00",
                "user_id": "user-1",
                "user_principal_name": "admin@example.test",
                "department": "Security",
                "role": "Global Admin",
                "event_type": "role_assigned",
                "risk_hint": "high",
            },
            {
                "event_id": "id-2",
                "timestamp": "2026-01-02T00:00:00+00:00",
                "user_id": "user-2",
                "user_principal_name": "guest@example.test",
                "department": "External",
                "role": "User",
                "event_type": "guest_invited",
                "risk_hint": "normal",
            },
            {
                "event_id": "id-3",
                "timestamp": "2026-01-03T00:00:00+00:00",
                "user_id": "user-3",
                "user_principal_name": "user@example.test",
                "department": "Finance",
                "role": "User",
                "event_type": "mfa_disabled",
                "risk_hint": "elevated",
            },
        ]
    )


def test_dormant_user_check() -> None:
    logins = pd.DataFrame(
        [
            {
                "user_id": "user-1",
                "timestamp": "2026-01-01T00:00:00+00:00",
                "login_status": "success",
            }
        ]
    )

    findings = check_dormant_users(
        _identity_events(),
        logins,
        check_timestamp=TIMESTAMP,
        reference_time=REFERENCE_TIME,
        inactivity_days=10,
    )

    assert findings
    assert findings[0]["evidence"]


def test_dormant_privileged_account_check() -> None:
    logins = pd.DataFrame(columns=["user_id", "timestamp", "login_status"])

    findings = check_dormant_privileged_accounts(
        _identity_events(),
        logins,
        check_timestamp=TIMESTAMP,
        reference_time=REFERENCE_TIME,
        inactivity_days=30,
        privileged_roles=PRIVILEGED_ROLES,
    )

    assert any(finding["finding_category"] == "dormant_privileged_account" for finding in findings)


def test_mfa_disabled_check() -> None:
    findings = check_mfa_disabled_or_missing(_identity_events(), check_timestamp=TIMESTAMP)

    assert any(finding["finding_category"] == "mfa_gap" for finding in findings)


def test_guest_exposure_check() -> None:
    application_events = pd.DataFrame(
        [{"user_id": "user-2", "event_id": "app-1", "event_type": "file_download"}]
    )
    cloud_activity = pd.DataFrame(columns=["caller"])

    findings = check_guest_user_exposure(
        _identity_events(),
        application_events,
        cloud_activity,
        check_timestamp=TIMESTAMP,
        privileged_roles=PRIVILEGED_ROLES,
    )

    assert findings[0]["identity_type"] == "Guest"
    assert findings[0]["evidence"]["application_event_count"] == 1


def test_role_sprawl_check() -> None:
    identity_events = pd.concat(
        [
            _identity_events(),
            pd.DataFrame(
                [
                    {
                        "event_id": "id-4",
                        "timestamp": "2026-01-04T00:00:00+00:00",
                        "user_id": "user-1",
                        "user_principal_name": "admin@example.test",
                        "department": "Security",
                        "role": "Global Admin",
                        "event_type": "privileged_role_activated",
                        "risk_hint": "high",
                    }
                ]
            ),
        ]
    )

    findings = check_role_sprawl(identity_events, check_timestamp=TIMESTAMP, threshold=2)

    assert len(findings) == 1
    assert findings[0]["evidence"]["role_event_count"] == 2


def test_risky_privilege_assignment_check() -> None:
    findings = check_risky_privilege_assignment(
        _identity_events(),
        check_timestamp=TIMESTAMP,
        privileged_roles=PRIVILEGED_ROLES,
        risky_risk_hints={"high", "elevated"},
    )

    assert len(findings) == 1
    assert findings[0]["finding_category"] == "risky_privilege_assignment"


def test_privileged_cloud_activity_check() -> None:
    cloud_activity = pd.DataFrame(
        [
            {
                "event_id": "cloud-1",
                "caller": "admin@example.test",
                "operation_name": "diagnostic_setting_disabled",
                "resource_name": "diagnostics",
                "severity": "critical",
                "risk_hint": "high",
            }
        ]
    )

    findings = check_privileged_cloud_activity(
        _identity_events(),
        cloud_activity,
        check_timestamp=TIMESTAMP,
        privileged_roles=PRIVILEGED_ROLES,
    )

    assert len(findings) == 1
    assert findings[0]["source_datasets"] == ["identity_events", "cloud_activity"]

