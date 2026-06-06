"""Command-line interface for the local security intelligence scaffold."""

import argparse
import pprint

from security_intelligence.config import load_yaml_config
from security_intelligence.copilot.engine import generate_copilot_briefs
from security_intelligence.dashboard.exporter import export_dashboard_data
from security_intelligence.detections.engine import run_detections
from security_intelligence.identity.engine import run_identity_checks
from security_intelligence.ingestion.pipeline import ingest_telemetry
from security_intelligence.monitoring.engine import monitor_platform
from security_intelligence.paths import CONFIG_DIR, DATA_DIR, OUTPUT_DIR, REPORTS_DIR
from security_intelligence.risk.engine import score_risk
from security_intelligence.telemetry.generator import generate_telemetry
from security_intelligence.validation.validator import validate_telemetry


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="security-intelligence",
        description="Local-first Azure Enterprise Security Intelligence Platform CLI.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser(
        "health-check",
        help="Confirm the local platform scaffold is ready.",
    )
    subparsers.add_parser(
        "show-config",
        help="Print the parsed local platform configuration.",
    )
    generate_parser = subparsers.add_parser(
        "generate-telemetry",
        help="Generate local synthetic security telemetry JSONL datasets.",
    )
    generate_parser.add_argument(
        "--output-dir",
        default=str(DATA_DIR / "raw"),
        help="Directory where generated JSONL files will be written.",
    )
    generate_parser.add_argument(
        "--days",
        type=int,
        default=30,
        help="Number of synthetic days to generate.",
    )
    generate_parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Deterministic random seed.",
    )
    generate_parser.add_argument(
        "--users",
        type=int,
        default=50,
        help="Number of synthetic users to generate.",
    )
    ingest_parser = subparsers.add_parser(
        "ingest-telemetry",
        help="Ingest raw synthetic telemetry JSONL files into processed CSV outputs.",
    )
    ingest_parser.add_argument(
        "--input-dir",
        default=str(DATA_DIR / "raw"),
        help="Directory containing raw JSONL telemetry files.",
    )
    ingest_parser.add_argument(
        "--output-dir",
        default=str(DATA_DIR / "processed"),
        help="Directory where processed CSV files will be written.",
    )
    ingest_parser.add_argument(
        "--summary-path",
        default="outputs/ingestion_summary.json",
        help="Path where the ingestion summary JSON will be written.",
    )
    validate_parser = subparsers.add_parser(
        "validate-telemetry",
        help="Validate processed telemetry CSV files and write data quality evidence.",
    )
    validate_parser.add_argument(
        "--input-dir",
        default=str(DATA_DIR / "processed"),
        help="Directory containing processed telemetry CSV files.",
    )
    validate_parser.add_argument(
        "--summary-path",
        default=str(OUTPUT_DIR / "data_quality_summary.json"),
        help="Path where the data quality summary JSON will be written.",
    )
    validate_parser.add_argument(
        "--report-path",
        default=str(REPORTS_DIR / "data_quality_report.md"),
        help="Path where the Markdown data quality report will be written.",
    )
    detections_parser = subparsers.add_parser(
        "run-detections",
        help="Run deterministic threat detection rules against processed telemetry.",
    )
    detections_parser.add_argument(
        "--input-dir",
        default=str(DATA_DIR / "processed"),
        help="Directory containing processed telemetry CSV files.",
    )
    detections_parser.add_argument(
        "--output-path",
        default=str(OUTPUT_DIR / "security_findings.json"),
        help="Path where machine-readable security findings JSON will be written.",
    )
    detections_parser.add_argument(
        "--report-path",
        default=str(REPORTS_DIR / "security_findings_report.md"),
        help="Path where the Markdown security findings report will be written.",
    )
    identity_parser = subparsers.add_parser(
        "run-identity-checks",
        help="Run deterministic identity governance checks against processed telemetry.",
    )
    identity_parser.add_argument(
        "--input-dir",
        default=str(DATA_DIR / "processed"),
        help="Directory containing processed telemetry CSV files.",
    )
    identity_parser.add_argument(
        "--output-path",
        default=str(OUTPUT_DIR / "identity_governance_findings.json"),
        help="Path where identity governance findings JSON will be written.",
    )
    identity_parser.add_argument(
        "--review-path",
        default=str(OUTPUT_DIR / "identity_review.csv"),
        help="Path where flattened identity review CSV will be written.",
    )
    identity_parser.add_argument(
        "--report-path",
        default=str(REPORTS_DIR / "identity_governance_report.md"),
        help="Path where the Markdown identity governance report will be written.",
    )
    identity_parser.add_argument(
        "--inactivity-days",
        type=int,
        default=30,
        help="Number of days without successful login considered dormant.",
    )
    risk_parser = subparsers.add_parser(
        "score-risk",
        help="Calculate deterministic entity risk scores from local evidence outputs.",
    )
    risk_parser.add_argument(
        "--security-findings-path",
        default=str(OUTPUT_DIR / "security_findings.json"),
        help="Path to security findings JSON.",
    )
    risk_parser.add_argument(
        "--identity-findings-path",
        default=str(OUTPUT_DIR / "identity_governance_findings.json"),
        help="Path to identity governance findings JSON.",
    )
    risk_parser.add_argument(
        "--data-quality-path",
        default=str(OUTPUT_DIR / "data_quality_summary.json"),
        help="Path to data quality summary JSON.",
    )
    risk_parser.add_argument(
        "--input-dir",
        default=str(DATA_DIR / "processed"),
        help="Directory containing processed telemetry CSV files for enrichment.",
    )
    risk_parser.add_argument(
        "--output-path",
        default=str(OUTPUT_DIR / "risk_scores.json"),
        help="Path where risk scores JSON will be written.",
    )
    risk_parser.add_argument(
        "--csv-path",
        default=str(OUTPUT_DIR / "risk_scores.csv"),
        help="Path where flattened risk scores CSV will be written.",
    )
    risk_parser.add_argument(
        "--report-path",
        default=str(REPORTS_DIR / "risk_scoring_report.md"),
        help="Path where the Markdown risk scoring report will be written.",
    )
    monitor_parser = subparsers.add_parser(
        "monitor-platform",
        help="Generate local operational health and evidence outputs.",
    )
    monitor_parser.add_argument(
        "--outputs-dir",
        default=str(OUTPUT_DIR),
        help="Directory containing pipeline output artifacts.",
    )
    monitor_parser.add_argument(
        "--reports-dir",
        default=str(REPORTS_DIR),
        help="Directory containing report artifacts.",
    )
    monitor_parser.add_argument(
        "--health-path",
        default=str(OUTPUT_DIR / "operational_health_summary.json"),
        help="Path where operational health JSON will be written.",
    )
    monitor_parser.add_argument(
        "--manifest-path",
        default=str(OUTPUT_DIR / "evidence_manifest.json"),
        help="Path where evidence manifest JSON will be written.",
    )
    monitor_parser.add_argument(
        "--report-path",
        default=str(REPORTS_DIR / "operational_evidence_report.md"),
        help="Path where operational evidence Markdown report will be written.",
    )
    monitor_parser.add_argument(
        "--freshness-hours",
        type=int,
        default=24,
        help="Warn when artifacts are older than this many hours.",
    )
    monitor_parser.add_argument(
        "--quality-threshold",
        type=float,
        default=90,
        help="Warn when data quality score is below this threshold.",
    )
    copilot_parser = subparsers.add_parser(
        "generate-copilot-briefs",
        help="Generate local simulated GenAI-style investigation copilot reports.",
    )
    copilot_parser.add_argument(
        "--outputs-dir",
        default=str(OUTPUT_DIR),
        help="Directory containing platform output artifacts.",
    )
    copilot_parser.add_argument(
        "--reports-dir",
        default=str(REPORTS_DIR),
        help="Directory where copilot Markdown reports will be written.",
    )
    copilot_parser.add_argument(
        "--context-path",
        default=str(OUTPUT_DIR / "copilot_context.json"),
        help="Path where copilot context JSON will be written.",
    )
    dashboard_parser = subparsers.add_parser(
        "export-dashboard-data",
        help="Export local dashboard-ready CSV datasets and reporting artifacts.",
    )
    dashboard_parser.add_argument(
        "--outputs-dir",
        default=str(OUTPUT_DIR),
        help="Directory containing platform output artifacts.",
    )
    dashboard_parser.add_argument(
        "--dashboard-dir",
        default="dashboards",
        help="Directory where dashboard documentation and summary will be written.",
    )
    dashboard_parser.add_argument(
        "--exports-dir",
        default="dashboards/exports",
        help="Directory where dashboard CSV exports will be written.",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "health-check":
        print("Azure Enterprise Security Intelligence Platform scaffold is ready.")
        return 0

    if args.command == "show-config":
        config = load_yaml_config(CONFIG_DIR / "platform.yaml")
        pprint.pp(config, sort_dicts=False)
        return 0

    if args.command == "generate-telemetry":
        counts = generate_telemetry(
            output_dir=args.output_dir,
            days=args.days,
            seed=args.seed,
            users=args.users,
        )
        print("Synthetic telemetry generated:")
        for dataset_name, record_count in counts.items():
            print(f"- {dataset_name}: {record_count} records")
        return 0

    if args.command == "ingest-telemetry":
        summary = ingest_telemetry(
            input_dir=args.input_dir,
            output_dir=args.output_dir,
            summary_path=args.summary_path,
        )
        print("Telemetry ingestion complete:")
        for dataset in summary["datasets"]:
            print(f"- {dataset['dataset_name']}: {dataset['record_count']} records")
        print(f"Total records ingested: {summary['total_records_ingested']}")
        return 0

    if args.command == "validate-telemetry":
        summary = validate_telemetry(
            input_dir=args.input_dir,
            summary_path=args.summary_path,
            report_path=args.report_path,
        )
        print("Telemetry validation complete:")
        for dataset in summary["datasets_validated"]:
            print(
                f"- {dataset['dataset_name']}: {dataset['status']} "
                f"({dataset['data_quality_score']:.1f}/100)"
            )
        print(f"Overall data quality score: {summary['overall_data_quality_score']:.1f}/100")
        return 0

    if args.command == "run-detections":
        summary = run_detections(
            input_dir=args.input_dir,
            output_path=args.output_path,
            report_path=args.report_path,
        )
        print("Threat detections complete:")
        print(f"Total findings: {summary['total_findings']}")
        for severity, count in summary["findings_by_severity"].items():
            print(f"- {severity}: {count}")
        return 0

    if args.command == "run-identity-checks":
        summary = run_identity_checks(
            input_dir=args.input_dir,
            output_path=args.output_path,
            review_path=args.review_path,
            report_path=args.report_path,
            inactivity_days=args.inactivity_days,
        )
        print("Identity governance checks complete:")
        print(f"Total findings: {summary['total_findings']}")
        print("Findings by severity:")
        for severity, count in summary["findings_by_severity"].items():
            print(f"- {severity}: {count}")
        print("Findings by category:")
        for category, count in summary["findings_by_category"].items():
            print(f"- {category}: {count}")
        return 0

    if args.command == "score-risk":
        summary = score_risk(
            security_findings_path=args.security_findings_path,
            identity_findings_path=args.identity_findings_path,
            data_quality_path=args.data_quality_path,
            input_dir=args.input_dir,
            output_path=args.output_path,
            csv_path=args.csv_path,
            report_path=args.report_path,
        )
        print("Risk scoring complete:")
        print(f"Total entities scored: {summary['total_entities_scored']}")
        for band, count in summary["risk_band_counts"].items():
            print(f"- {band}: {count}")
        return 0

    if args.command == "monitor-platform":
        result = monitor_platform(
            outputs_dir=args.outputs_dir,
            reports_dir=args.reports_dir,
            health_path=args.health_path,
            manifest_path=args.manifest_path,
            report_path=args.report_path,
            freshness_hours=args.freshness_hours,
            quality_threshold=args.quality_threshold,
        )
        health = result["health_summary"]
        print("Platform monitoring complete:")
        print(f"Overall status: {health['overall_status']}")
        print(f"Warnings: {len(health['warnings'])}")
        print(f"Failures: {len(health['failures'])}")
        print("Key metrics:")
        for metric, value in health["key_metrics"].items():
            print(f"- {metric}: {value}")
        return 0

    if args.command == "generate-copilot-briefs":
        result = generate_copilot_briefs(
            outputs_dir=args.outputs_dir,
            reports_dir=args.reports_dir,
            context_path=args.context_path,
        )
        print("Local simulated copilot briefs generated:")
        print(f"Context: {result['context_path']}")
        for prompt_type, report_path in result["generated_reports"].items():
            print(f"- {prompt_type}: {report_path}")
        return 0

    if args.command == "export-dashboard-data":
        result = export_dashboard_data(
            outputs_dir=args.outputs_dir,
            dashboard_dir=args.dashboard_dir,
            exports_dir=args.exports_dir,
        )
        print("Dashboard exports generated:")
        for path in result["exports_created"]:
            print(f"- {path}")
        print("Executive metrics:")
        for metric in result["executive_metrics"]:
            print(f"- {metric['metric_name']}: {metric['metric_value']}")
        return 0

    parser.error(f"Unsupported command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
