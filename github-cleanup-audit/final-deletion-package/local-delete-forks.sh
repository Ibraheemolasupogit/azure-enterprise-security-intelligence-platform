#!/usr/bin/env bash
set -euo pipefail

# macOS usage:
# 1. Install GitHub CLI if needed: brew install gh
# 2. Authenticate with delete permissions: gh auth login
# 3. From the repository root, run:
#      bash github-cleanup-audit/final-deletion-package/local-delete-forks.sh
#
# This script is destructive only after you type exactly DELETE-FORKS.
# It reads the final audit CSVs, verifies that no keep repository appears in
# the delete list, and logs every attempted deletion.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DELETE_CSV="$SCRIPT_DIR/final-delete-candidates.csv"
KEEP_CSV="$SCRIPT_DIR/final-keep-list.csv"
REFERENCE_CSV="$SCRIPT_DIR/preserved-reference-index.csv"
LOG_CSV="$SCRIPT_DIR/deletion-log.csv"

CURRENT_AUDIT_REPO="Ibraheemolasupogit/azure-enterprise-security-intelligence-platform"
BATCH_SIZE=25

if ! command -v gh >/dev/null 2>&1; then
  echo "ERROR: GitHub CLI 'gh' is not installed or not on PATH." >&2
  echo "Install it on macOS with: brew install gh" >&2
  exit 1
fi

for file in "$DELETE_CSV" "$KEEP_CSV" "$REFERENCE_CSV"; do
  if [[ ! -f "$file" ]]; then
    echo "ERROR: required file not found: $file" >&2
    exit 1
  fi
done

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

KEEP_LIST="$TMP_DIR/keep.tsv"
DELETE_LIST="$TMP_DIR/delete.tsv"
OVERLAP_LIST="$TMP_DIR/overlap.tsv"

python3 - "$KEEP_CSV" "$DELETE_CSV" "$KEEP_LIST" "$DELETE_LIST" "$OVERLAP_LIST" <<'PY'
import csv
import re
import sys

keep_csv, delete_csv, keep_out, delete_out, overlap_out = sys.argv[1:]

def repo_full_name(url):
    match = re.match(r"^https://github\.com/([^/]+/[^/]+)/?$", url or "")
    return match.group(1) if match else ""

def read_rows(path):
    with open(path, newline="") as handle:
        return list(csv.DictReader(handle))

keep_rows = read_rows(keep_csv)
delete_rows = read_rows(delete_csv)

for row in keep_rows:
    row["_full_name"] = repo_full_name(row.get("repository URL", ""))

for row in delete_rows:
    row["_full_name"] = repo_full_name(row.get("repository URL", ""))

keep_full_names = {row["_full_name"] for row in keep_rows if row["_full_name"]}
delete_full_names = {row["_full_name"] for row in delete_rows if row["_full_name"]}
overlap = sorted(keep_full_names & delete_full_names)

with open(keep_out, "w", newline="") as handle:
    for row in keep_rows:
        handle.write(f"{row.get('repository name','')}\t{row.get('repository URL','')}\t{row.get('_full_name','')}\n")

with open(delete_out, "w", newline="") as handle:
    for row in delete_rows:
        handle.write(f"{row.get('repository name','')}\t{row.get('repository URL','')}\t{row.get('_full_name','')}\n")

with open(overlap_out, "w", newline="") as handle:
    for full_name in overlap:
        handle.write(full_name + "\n")
PY

KEEP_COUNT="$(wc -l < "$KEEP_LIST" | tr -d ' ')"
DELETE_COUNT="$(wc -l < "$DELETE_LIST" | tr -d ' ')"
OVERLAP_COUNT="$(wc -l < "$OVERLAP_LIST" | tr -d ' ')"

echo "Repositories that will be kept ($KEEP_COUNT):"
awk -F '\t' '{ printf "  - %s (%s)\n", $1, $2 }' "$KEEP_LIST"
echo
echo "Total repositories to delete: $DELETE_COUNT"
echo

if [[ "$KEEP_COUNT" != "7" ]]; then
  echo "ERROR: expected exactly 7 keep repositories, found $KEEP_COUNT." >&2
  exit 1
fi

if [[ "$OVERLAP_COUNT" != "0" ]]; then
  echo "ERROR: one or more kept repositories appear in the delete list. Stopping immediately." >&2
  cat "$OVERLAP_LIST" >&2
  exit 1
fi

if awk -F '\t' -v current="$CURRENT_AUDIT_REPO" '$3 == current { found=1 } END { exit found ? 0 : 1 }' "$DELETE_LIST"; then
  echo "ERROR: current audit repository appears in delete list: $CURRENT_AUDIT_REPO" >&2
  echo "Stopping to prevent deleting the repository containing this audit." >&2
  exit 1
fi

echo "Safety checks passed:"
echo "  - No keep repositories appear in the delete list."
echo "  - Current audit repository is not in the delete list."
echo
echo "This will delete $DELETE_COUNT GitHub repositories using: gh repo delete <owner/repo> --yes"
echo "Type exactly DELETE-FORKS to continue:"
read -r CONFIRMATION

if [[ "$CONFIRMATION" != "DELETE-FORKS" ]]; then
  echo "Confirmation did not match. No repositories were deleted."
  exit 1
fi

printf 'repo name,repo URL,deletion status,timestamp,error message if any\n' > "$LOG_CSV"

attempted=0
deleted=0
failed=0
skipped=0
batch_number=1
batch_count=0

csv_escape() {
  python3 - "$1" <<'PY'
import csv
import io
import sys

buf = io.StringIO()
writer = csv.writer(buf)
writer.writerow([sys.argv[1]])
print(buf.getvalue().strip())
PY
}

log_result() {
  local repo_name="$1"
  local repo_url="$2"
  local status="$3"
  local message="$4"
  local timestamp
  timestamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  printf '%s,%s,%s,%s,%s\n' \
    "$(csv_escape "$repo_name")" \
    "$(csv_escape "$repo_url")" \
    "$(csv_escape "$status")" \
    "$(csv_escape "$timestamp")" \
    "$(csv_escape "$message")" >> "$LOG_CSV"
}

while IFS=$'\t' read -r repo_name repo_url repo_full_name; do
  if [[ -z "$repo_full_name" ]]; then
    skipped=$((skipped + 1))
    log_result "$repo_name" "$repo_url" "SKIPPED" "Could not parse owner/repo from repository URL."
    continue
  fi

  if [[ "$repo_full_name" == "$CURRENT_AUDIT_REPO" ]]; then
    skipped=$((skipped + 1))
    log_result "$repo_name" "$repo_url" "SKIPPED" "Skipped current audit repository."
    continue
  fi

  if (( batch_count == 0 )); then
    echo "Starting batch $batch_number..."
  fi

  attempted=$((attempted + 1))
  echo "Deleting $attempted/$DELETE_COUNT: $repo_full_name"

  error_file="$TMP_DIR/error-$attempted.txt"
  if gh repo delete "$repo_full_name" --yes 2>"$error_file"; then
    deleted=$((deleted + 1))
    log_result "$repo_name" "$repo_url" "DELETED" ""
  else
    failed=$((failed + 1))
    error_message="$(tr '\n' ' ' < "$error_file" | sed 's/[[:space:]]\+/ /g')"
    log_result "$repo_name" "$repo_url" "FAILED" "$error_message"
    echo "  FAILED: $error_message" >&2
  fi

  batch_count=$((batch_count + 1))
  if (( batch_count == BATCH_SIZE )); then
    echo "Completed batch $batch_number."
    batch_number=$((batch_number + 1))
    batch_count=0
  fi
done < "$DELETE_LIST"

if (( batch_count > 0 )); then
  echo "Completed batch $batch_number."
fi

echo
echo "Deletion run complete."
echo "Total attempted: $attempted"
echo "Total deleted: $deleted"
echo "Total failed: $failed"
echo "Total skipped: $skipped"
echo "Deletion log: $LOG_CSV"
