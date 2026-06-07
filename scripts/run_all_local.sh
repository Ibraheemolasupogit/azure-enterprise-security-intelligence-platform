#!/usr/bin/env bash
set -euo pipefail

# Run the full local workflow with synthetic data only.
# This script does not require Azure CLI, cloud credentials, Terraform, or Bicep.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
export PYTHONPATH="${PROJECT_ROOT}/src:${PYTHONPATH:-}"

cd "${PROJECT_ROOT}"

echo "== Quality checks =="
python3 -m pytest
python3 -m ruff check .

echo "== Platform health =="
python3 -m security_intelligence.cli health-check

echo "== Generate telemetry =="
python3 -m security_intelligence.cli generate-telemetry --days 30 --users 50 --seed 42

echo "== Ingest telemetry =="
python3 -m security_intelligence.cli ingest-telemetry --input-dir data/raw --output-dir data/processed

echo "== Validate telemetry =="
python3 -m security_intelligence.cli validate-telemetry --input-dir data/processed

echo "== Run detections =="
python3 -m security_intelligence.cli run-detections --input-dir data/processed

echo "== Run identity governance checks =="
python3 -m security_intelligence.cli run-identity-checks --input-dir data/processed

echo "== Score risk =="
python3 -m security_intelligence.cli score-risk

echo "== Monitor platform =="
python3 -m security_intelligence.cli monitor-platform

echo "== Generate local copilot briefs =="
python3 -m security_intelligence.cli generate-copilot-briefs

echo "== Export dashboard data =="
python3 -m security_intelligence.cli export-dashboard-data

echo "== Local workflow complete =="

