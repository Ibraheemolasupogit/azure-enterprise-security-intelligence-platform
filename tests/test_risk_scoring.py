from security_intelligence.risk.scoring import (
    DEFAULT_GOVERNANCE_CATEGORY_WEIGHTS,
    DEFAULT_RISK_BANDS,
    DEFAULT_SEVERITY_WEIGHTS,
    assign_risk_band,
    cap_score,
    score_governance_categories,
    score_severities,
)


def test_severity_weighting_logic() -> None:
    score, factors = score_severities({"critical": 1, "high": 2}, DEFAULT_SEVERITY_WEIGHTS)

    assert score == 70
    assert "1 critical findings (+30)" in factors
    assert "2 high findings (+40)" in factors


def test_governance_category_weighting_logic() -> None:
    score, factors = score_governance_categories(
        {"mfa_gap": 1, "risky_privilege_assignment": 1},
        DEFAULT_GOVERNANCE_CATEGORY_WEIGHTS,
    )

    assert score == 40
    assert "1 mfa_gap findings (+15)" in factors


def test_risk_band_assignment() -> None:
    assert assign_risk_band(10, DEFAULT_RISK_BANDS) == "low"
    assert assign_risk_band(40, DEFAULT_RISK_BANDS) == "medium"
    assert assign_risk_band(60, DEFAULT_RISK_BANDS) == "high"
    assert assign_risk_band(90, DEFAULT_RISK_BANDS) == "critical"


def test_score_cap_at_100() -> None:
    assert cap_score(140, 100) == 100

