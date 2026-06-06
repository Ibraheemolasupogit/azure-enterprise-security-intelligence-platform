from pathlib import Path

from security_intelligence.dashboard.datasets import load_dashboard_payloads
from security_intelligence.dashboard.metrics import REQUIRED_METRICS, build_executive_metrics
from tests.test_dashboard_support import build_full_dashboard_chain


def test_executive_summary_metrics_contain_required_metrics(tmp_path: Path) -> None:
    outputs, _ = build_full_dashboard_chain(tmp_path)
    payloads = load_dashboard_payloads(outputs)

    metrics = build_executive_metrics(payloads)

    metric_names = {metric["metric_name"] for metric in metrics}
    assert set(REQUIRED_METRICS).issubset(metric_names)
    assert all("source_artifact" in metric for metric in metrics)

