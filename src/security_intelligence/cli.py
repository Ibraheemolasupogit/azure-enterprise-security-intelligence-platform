"""Command-line interface for the local security intelligence scaffold."""

import argparse
import pprint

from security_intelligence.config import load_yaml_config
from security_intelligence.paths import CONFIG_DIR, DATA_DIR
from security_intelligence.telemetry.generator import generate_telemetry


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

    parser.error(f"Unsupported command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
