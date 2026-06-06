"""Optional local Streamlit placeholder for dashboard exports."""

from pathlib import Path

import pandas as pd

try:
    import streamlit as st
except ModuleNotFoundError:  # pragma: no cover - Streamlit is optional.
    st = None


EXPORTS_DIR = Path(__file__).parent / "exports"


def load_csv(name: str) -> pd.DataFrame:
    path = EXPORTS_DIR / name
    if not path.exists():
        return pd.DataFrame()
    return pd.read_csv(path)


def main() -> None:
    if st is None:
        print("Streamlit is not installed. Install streamlit to run this optional dashboard.")
        return

    st.title("Azure Enterprise Security Intelligence Platform")
    st.caption("Local-first dashboard placeholder using exported CSV files.")

    metrics = load_csv("executive_summary_metrics.csv")
    risks = load_csv("risk_scores_dashboard.csv")
    security = load_csv("security_findings_dashboard.csv")
    identity = load_csv("identity_governance_dashboard.csv")
    health = load_csv("operational_health_dashboard.csv")

    st.header("Executive Metrics")
    st.dataframe(metrics)
    st.header("Top Risk Scores")
    st.dataframe(risks.head(20))
    st.header("Security Findings")
    st.dataframe(security.head(20))
    st.header("Identity Governance")
    st.dataframe(identity.head(20))
    st.header("Operational Health")
    st.dataframe(health)


if __name__ == "__main__":
    main()
