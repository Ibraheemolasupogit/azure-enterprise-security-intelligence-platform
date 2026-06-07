const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");
const raw = __dirname;
const forks = JSON.parse(fs.readFileSync(path.join(raw, "forks-compact.json"), "utf8"));

function safeName(name) {
  return name.replace(/[\/ ]/g, "_");
}

function readUpstream(repo) {
  const file = path.join(raw, "pages", `${safeName(repo.name)}.html`);
  let html = "";
  try {
    html = fs.readFileSync(file, "utf8");
  } catch {
    return "";
  }
  const parent = html.match(/repository_parent_nwo" content="([^"]+)/);
  const rootRepo = html.match(/repository_network_root_nwo" content="([^"]+)/);
  return parent?.[1] || rootRepo?.[1] || "";
}

function daysBetween(a, b) {
  return (new Date(b).getTime() - new Date(a).getTime()) / 86400000;
}

function textOf(repo) {
  return [repo.name, repo.description, repo.homepage, repo.language, ...(repo.topics || [])]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

function valueSignal(repo) {
  const text = textOf(repo);
  const learning = /\b(mslearn|microsoftlearning|microsoft learn|lab|labs|course|workshop|tutorial|bootcamp|training|learn|guide|exam|certification|copilot|github actions|sample|samples|example|examples|kaggle|debugging|administrator|az-|dp-|sc-|pl-|ms-|mb-|md-|apl-)\b/i.test(text);
  const portfolio = /\b(portfolio|personal project|fraud|risk|security|cyber|cyberthreats|defender|entra|xdr|devops|healthcare|nhs|mlops|machine learning|ai|agent|agents|rag|nlp|computer vision|data engineering|analytics|power bi|azure|aws|amazon|gcp|google cloud|snowflake|databricks|kubernetes|postgres|spacy|apache|vue|forecasting|regression|prediction|predictive|model|dataset)\b/i.test(text);
  const contribution = /\b(contribution|pull request|apache|kubernetes|postgres|spacy|vue|framework|open-source|oss)\b/i.test(text);

  const bits = [];
  if (portfolio) bits.push("portfolio/reference");
  if (learning) bits.push("learning");
  if (contribution) bits.push("contribution/reference");
  return bits.length ? bits.join("; ") : "No clear signal";
}

function uniqueEvidence(repo) {
  const created = repo.created_at;
  const updated = repo.updated_at;
  const pushed = repo.pushed_at;
  if (!created || !pushed) return "Uncertain";

  const pushedAfterCreate = daysBetween(created, pushed) >= -0.05;
  const updatedLater = updated && daysBetween(created, updated) > 1;
  const hasOwnMetadata = Boolean((repo.description && repo.description.trim()) || (repo.homepage && repo.homepage.trim()) || (repo.topics || []).length);

  if (pushedAfterCreate) {
    return "Possible: fork branch has pushes at/after fork creation; could be user work or a sync";
  }
  if (updatedLater && hasOwnMetadata) {
    return "Possible: metadata or repository activity changed after fork creation";
  }
  if (updatedLater) {
    return "Uncertain: repository updated after fork creation, but no commit comparison available";
  }
  return "No obvious unique commits from public metadata";
}

function recommendation(repo, unique, value) {
  const weakValue = value === "No clear signal";
  const noUnique = unique.startsWith("No obvious");
  const emptyish = repo.size <= 1000 && !repo.description && !repo.homepage && !repo.language && !(repo.topics || []).length;
  const oldUntouched = noUnique && daysBetween(repo.created_at, repo.updated_at) <= 1;

  if (noUnique && weakValue && emptyish && oldUntouched && repo.size <= 100) {
    return ["DELETE", "Appears to be an untouched, low-signal fork with no clear learning, portfolio, or contribution value."];
  }
  if (value.includes("portfolio") || value.includes("contribution")) {
    return ["KEEP", `Shows ${value} value; preserve unless a manual review finds it duplicated elsewhere.`];
  }
  if (value.includes("learning") && !noUnique) {
    return ["KEEP", "Learning-oriented fork with possible activity after creation."];
  }
  if (value.includes("learning")) {
    return ["REVIEW", "Learning/reference fork; review before deleting even if no unique commits are obvious."];
  }
  return ["REVIEW", "Evidence is uncertain or incomplete; review manually before deletion."];
}

function csvEscape(value) {
  const s = String(value ?? "");
  return /[",\n]/.test(s) ? `"${s.replaceAll('"', '""')}"` : s;
}

const rows = forks.map((repo) => {
  const upstream = readUpstream(repo);
  const unique = uniqueEvidence(repo);
  const value = valueSignal(repo);
  const [rec, reason] = recommendation(repo, unique, value);
  return {
    "repository name": repo.name,
    "repository URL": repo.html_url,
    "whether it is a fork": "Yes",
    "upstream/original repository if available": upstream ? `https://github.com/${upstream}` : "Unavailable",
    "last updated date": repo.updated_at,
    "visibility": repo.visibility || "public",
    "whether there appear to be unique commits or meaningful changes by me": unique,
    "whether there are signs of portfolio value, learning value, or contribution value": value,
    "recommendation": rec,
    "short reason for the recommendation": reason,
  };
});

rows.sort((a, b) => {
  const order = { DELETE: 0, REVIEW: 1, KEEP: 2 };
  return order[a.recommendation] - order[b.recommendation] || a["repository name"].localeCompare(b["repository name"]);
});

const headers = Object.keys(rows[0]);
const md = [
  "# GitHub Fork Cleanup Audit",
  "",
  `Generated: ${new Date().toISOString()}`,
  "",
  "Scope: public repositories visible through GitHub's public repository API plus repository page metadata. No repositories were deleted, archived, renamed, transferred, or modified.",
  "",
  "Unique-commit evidence is conservative: GitHub's public list/page data does not expose an authenticated ahead/behind comparison for every fork, so uncertain cases are marked REVIEW unless there is clear keep value.",
  "",
  `Summary: ${rows.length} forks found. DELETE: ${rows.filter((r) => r.recommendation === "DELETE").length}. REVIEW: ${rows.filter((r) => r.recommendation === "REVIEW").length}. KEEP: ${rows.filter((r) => r.recommendation === "KEEP").length}.`,
  "",
  `| ${headers.join(" | ")} |`,
  `| ${headers.map(() => "---").join(" | ")} |`,
  ...rows.map((row) => `| ${headers.map((h) => String(row[h]).replaceAll("|", "\\|").replace(/\s+/g, " ").trim()).join(" | ")} |`),
  "",
].join("\n");

fs.writeFileSync(path.join(root, "all-forks-audit.md"), md);

for (const rec of ["DELETE", "REVIEW", "KEEP"]) {
  const subset = rows.filter((row) => row.recommendation === rec);
  const csv = [
    headers.map(csvEscape).join(","),
    ...subset.map((row) => headers.map((h) => csvEscape(row[h])).join(",")),
    "",
  ].join("\n");
  fs.writeFileSync(path.join(root, `forks-to-${rec.toLowerCase()}.csv`), csv);
}

console.log(JSON.stringify({
  forks: rows.length,
  delete: rows.filter((r) => r.recommendation === "DELETE").length,
  review: rows.filter((r) => r.recommendation === "REVIEW").length,
  keep: rows.filter((r) => r.recommendation === "KEEP").length,
  upstreamFound: rows.filter((r) => !r["upstream/original repository if available"].endsWith("Unavailable")).length,
}, null, 2));
