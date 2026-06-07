const fs = require("fs");
const path = require("path");

const auditRoot = path.resolve(__dirname, "..");
const sourceDir = path.join(auditRoot, "sanitised-policy-review");
const outDir = path.join(auditRoot, "final-deletion-package");
fs.mkdirSync(outDir, { recursive: true });

function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = "";
  let quoted = false;

  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    const next = text[i + 1];
    if (quoted) {
      if (char === '"' && next === '"') {
        field += '"';
        i++;
      } else if (char === '"') {
        quoted = false;
      } else {
        field += char;
      }
    } else if (char === '"') {
      quoted = true;
    } else if (char === ",") {
      row.push(field);
      field = "";
    } else if (char === "\n") {
      row.push(field);
      if (row.length > 1 || row[0]) rows.push(row);
      row = [];
      field = "";
    } else if (char !== "\r") {
      field += char;
    }
  }

  if (field || row.length) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

function readCsv(file) {
  const rows = parseCsv(fs.readFileSync(file, "utf8"));
  const headers = rows[0];
  return rows.slice(1).map((row) => Object.fromEntries(headers.map((header, index) => [header, row[index] || ""])));
}

function csvEscape(value) {
  const text = String(value ?? "");
  return /[",\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

function writeCsv(file, headers, rows) {
  const csv = [
    headers.map(csvEscape).join(","),
    ...rows.map((row) => headers.map((header) => csvEscape(row[header])).join(",")),
    "",
  ].join("\n");
  fs.writeFileSync(path.join(outDir, file), csv);
}

function repoFullName(url) {
  const match = String(url).match(/^https:\/\/github\.com\/([^/]+\/[^/]+)\/?$/);
  return match ? match[1] : "";
}

const keep = readCsv(path.join(sourceDir, "forks-to-keep-explicit.csv"));
const review = readCsv(path.join(sourceDir, "forks-to-review-for-deletion.csv"));
const manual = readCsv(path.join(sourceDir, "manual-name-ambiguity-check.csv"));
const deleteCandidates = [...review, ...manual].sort((a, b) => a["repository name"].localeCompare(b["repository name"]));
const keepNames = new Set(keep.map((row) => row["repository name"]));
const accidentalKeepOverlap = deleteCandidates.filter((row) => keepNames.has(row["repository name"]));

const finalHeaders = [
  "repository name",
  "repository URL",
  "upstream/parent if available",
  "last updated date",
  "final decision",
  "source classification",
  "policy match",
  "reason",
];

const finalKeepRows = keep.map((row) => ({
  ...row,
  "final decision": "KEEP",
  "source classification": row.classification,
  "reason": row["short reason"],
}));

const finalDeleteRows = deleteCandidates.map((row) => ({
  ...row,
  "final decision": "DELETE-CANDIDATE",
  "source classification": row.classification,
  "reason": "Final policy keeps only the 7 explicit forks; this fork is not listed in forks-to-keep-explicit.csv.",
}));

const referenceHeaders = [
  "repository name",
  "repository URL",
  "upstream/original URL where available",
  "last updated date",
  "reason for deletion",
];

const referenceRows = finalDeleteRows.map((row) => ({
  "repository name": row["repository name"],
  "repository URL": row["repository URL"],
  "upstream/original URL where available": row["upstream/parent if available"],
  "last updated date": row["last updated date"],
  "reason for deletion": row.reason,
}));

writeCsv("final-keep-list.csv", finalHeaders, finalKeepRows);
writeCsv("final-delete-candidates.csv", finalHeaders, finalDeleteRows);
writeCsv("preserved-reference-index.csv", referenceHeaders, referenceRows);

const total = finalKeepRows.length + finalDeleteRows.length;
const summary = {
  totalForksReviewed: total,
  totalKept: finalKeepRows.length,
  totalDeletionCandidates: finalDeleteRows.length,
  totalPreservedInReferenceIndex: referenceRows.length,
  overlapBetweenKeepAndDelete: accidentalKeepOverlap.length,
};

const mdHeaders = finalHeaders;
const deleteMd = [
  "# Final Delete Candidates",
  "",
  "No repositories were deleted, archived, renamed, transferred, or modified.",
  "",
  `Summary: total forks reviewed: ${summary.totalForksReviewed}. Total kept: ${summary.totalKept}. Total deletion candidates: ${summary.totalDeletionCandidates}. Total preserved in reference index: ${summary.totalPreservedInReferenceIndex}.`,
  "",
  "Policy: keep only the 7 forks listed in `forks-to-keep-explicit.csv`; every other fork is a final deletion candidate.",
  "",
  `| ${mdHeaders.join(" | ")} |`,
  `| ${mdHeaders.map(() => "---").join(" | ")} |`,
  ...finalDeleteRows.map((row) => `| ${mdHeaders.map((header) => String(row[header]).replaceAll("|", "\\|").replace(/\s+/g, " ").trim()).join(" | ")} |`),
  "",
].join("\n");
fs.writeFileSync(path.join(outDir, "final-delete-candidates.md"), deleteMd);

const safety = [
  "# Deletion Safety Check",
  "",
  "No deletion has been performed.",
  "",
  "This package is a final audit package only. It does not delete, archive, rename, transfer, or modify any GitHub repository.",
  "",
  "## Count Summary",
  "",
  `- Total forks reviewed: ${summary.totalForksReviewed}`,
  `- Total kept: ${summary.totalKept}`,
  `- Total deletion candidates: ${summary.totalDeletionCandidates}`,
  `- Total preserved in reference index: ${summary.totalPreservedInReferenceIndex}`,
  `- Keep/delete overlap detected: ${summary.overlapBetweenKeepAndDelete}`,
  "",
  "## Policy Applied",
  "",
  "- Keep only the 7 explicit forks from `github-cleanup-audit/sanitised-policy-review/forks-to-keep-explicit.csv`.",
  "- Move every other forked repository to final deletion candidates.",
  "- Preserve repo URLs, upstream/original URLs, last updated dates, and deletion reasons in `preserved-reference-index.csv`.",
  "",
  "## Safety Notes",
  "",
  "- `delete-command-preview.sh` is intentionally disabled.",
  "- The script exits before any command section.",
  "- All `gh repo delete` lines are commented out.",
  "- A future manual deletion pass would require deliberate editing and separate execution by a human.",
  "",
].join("\n");
fs.writeFileSync(path.join(outDir, "deletion-safety-check.md"), safety);

const commandPreview = [
  "#!/usr/bin/env bash",
  "set -euo pipefail",
  "",
  "# PREVIEW ONLY: this script is intentionally disabled.",
  "# It must not delete anything unless a human manually edits it later.",
  "# No deletion commands are active in this file.",
  "",
  'echo "PREVIEW ONLY: no repositories will be deleted."',
  'echo "This script is intentionally disabled. Edit manually only after a separate final confirmation."',
  "exit 0",
  "",
  "# The commands below are commented out on purpose.",
  "# To use them in the future, you would need to manually review, edit, uncomment, and run them yourself.",
  "",
  ...finalDeleteRows.map((row) => `# gh repo delete ${repoFullName(row["repository URL"])} --yes`),
  "",
].join("\n");
fs.writeFileSync(path.join(outDir, "delete-command-preview.sh"), commandPreview, { mode: 0o644 });

console.log(JSON.stringify(summary, null, 2));
