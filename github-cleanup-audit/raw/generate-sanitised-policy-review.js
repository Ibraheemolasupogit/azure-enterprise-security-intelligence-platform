const fs = require("fs");
const path = require("path");

const auditRoot = path.resolve(__dirname, "..");
const outDir = path.join(auditRoot, "sanitised-policy-review");
fs.mkdirSync(outDir, { recursive: true });

const forks = JSON.parse(fs.readFileSync(path.join(__dirname, "forks-compact.json"), "utf8"));

function safeName(name) {
  return name.replace(/[\/ ]/g, "_");
}

function readHtml(repo) {
  const file = path.join(__dirname, "pages", `${safeName(repo.name)}.html`);
  try {
    return fs.readFileSync(file, "utf8");
  } catch {
    return "";
  }
}

function decodeHtml(text) {
  return text
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/<[^>]*>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function upstreamFromHtml(html) {
  const parent = html.match(/repository_parent_nwo" content="([^"]+)/);
  const root = html.match(/repository_network_root_nwo" content="([^"]+)/);
  return parent?.[1] || root?.[1] || "";
}

function readmeText(html) {
  const match = html.match(/<article class="markdown-body[\s\S]*?<\/article>/);
  return match ? decodeHtml(match[0]) : "";
}

function metadataText(repo, html) {
  const metaDescription = html.match(/<meta name="description" content="([^"]*)"/)?.[1] || "";
  return [
    repo.name,
    repo.full_name,
    repo.description,
    repo.homepage,
    repo.language,
    ...(repo.topics || []),
    metaDescription,
  ].filter(Boolean).join(" ");
}

function hasExplicitDay(text) {
  const normalized = text.toLowerCase();
  const day = normalized.match(/ai[\s._-]*102[\s\S]{0,120}\bday[\s._-]*([1-6])\b/)
    || normalized.match(/\bday[\s._-]*([1-6])\b[\s\S]{0,120}ai[\s._-]*102/);
  return day ? `AI-102 Day ${day[1]}` : "";
}

function hasAmbiguousAi102(text) {
  const normalized = text.toLowerCase();
  return /ai[\s._-]*102/.test(normalized) && !hasExplicitDay(text);
}

function hasExplicitPlayground(repo) {
  return /\bplay[\s._-]*ground\b/i.test(repo.name)
    || /\bplay[\s._-]*ground\b/i.test(repo.full_name);
}

function hasAmbiguousPlayground(metadata, readme) {
  return /\bplay[\s._-]*ground\b/i.test(metadata)
    || /\bplay[\s._-]*ground fork\b/i.test(readme)
    || /\bfork[\s\S]{0,80}\bplay[\s._-]*ground\b/i.test(readme);
}

function classify(repo) {
  const html = readHtml(repo);
  const upstream = upstreamFromHtml(html);
  const metadata = metadataText(repo, html);
  const readme = readmeText(html);
  const combined = `${metadata} ${readme}`;
  const explicitDay = hasExplicitDay(combined);

  if (explicitDay) {
    return {
      upstream,
      classification: "KEEP-EXPLICIT",
      match: explicitDay,
      reason: `Clearly matches the explicit keep policy for ${explicitDay}.`,
    };
  }

  if (hasExplicitPlayground(repo)) {
    return {
      upstream,
      classification: "KEEP-EXPLICIT",
      match: "Playground",
      reason: "Clearly matches the explicit keep policy for a Playground/play-ground/play ground fork.",
    };
  }

  if (hasAmbiguousAi102(combined)) {
    return {
      upstream,
      classification: "MANUAL-NAME-AMBIGUITY-CHECK",
      match: "Ambiguous AI-102",
      reason: "Mentions AI-102 but does not clearly identify Day 1 through Day 6 in the existing metadata/README evidence.",
    };
  }

  if (hasAmbiguousPlayground(metadata, readme)) {
    return {
      upstream,
      classification: "MANUAL-NAME-AMBIGUITY-CHECK",
      match: "Ambiguous Playground",
      reason: "README mentions Playground, but existing evidence does not clearly identify this as the Playground fork to keep.",
    };
  }

  return {
    upstream,
    classification: "REVIEW-FOR-DELETION",
    match: "No explicit keep-policy match",
    reason: "Does not clearly match AI-102 Day 1-6 or Playground under the sanitised cleanup policy.",
  };
}

function csvEscape(value) {
  const text = String(value ?? "");
  return /[",\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

const rows = forks.map((repo) => {
  const result = classify(repo);
  return {
    "repository name": repo.name,
    "repository URL": repo.html_url,
    "upstream/parent if available": result.upstream ? `https://github.com/${result.upstream}` : "Unavailable",
    "last updated date": repo.updated_at,
    "classification": result.classification,
    "policy match": result.match,
    "short reason": result.reason,
  };
}).sort((a, b) => {
  const order = {
    "KEEP-EXPLICIT": 0,
    "MANUAL-NAME-AMBIGUITY-CHECK": 1,
    "REVIEW-FOR-DELETION": 2,
  };
  return order[a.classification] - order[b.classification]
    || a["repository name"].localeCompare(b["repository name"]);
});

const headers = Object.keys(rows[0]);
const groups = {
  "forks-to-keep-explicit.csv": rows.filter((row) => row.classification === "KEEP-EXPLICIT"),
  "manual-name-ambiguity-check.csv": rows.filter((row) => row.classification === "MANUAL-NAME-AMBIGUITY-CHECK"),
  "forks-to-review-for-deletion.csv": rows.filter((row) => row.classification === "REVIEW-FOR-DELETION"),
};

for (const [filename, groupRows] of Object.entries(groups)) {
  const csv = [
    headers.map(csvEscape).join(","),
    ...groupRows.map((row) => headers.map((header) => csvEscape(row[header])).join(",")),
    "",
  ].join("\n");
  fs.writeFileSync(path.join(outDir, filename), csv);
}

const counts = {
  total: rows.length,
  keep: groups["forks-to-keep-explicit.csv"].length,
  review: groups["forks-to-review-for-deletion.csv"].length,
  manual: groups["manual-name-ambiguity-check.csv"].length,
};

const md = [
  "# Sanitised Fork Cleanup Policy Review",
  "",
  `Generated: ${new Date().toISOString()}`,
  "",
  "Source of truth: existing `github-cleanup-audit` files, including the fork metadata and cached repository pages under `github-cleanup-audit/raw/`.",
  "",
  "No repositories were deleted, archived, renamed, transferred, or modified.",
  "",
  "Policy: KEEP only forks that clearly match AI-102 Day 1 through Day 6, or a Playground/play-ground/play ground fork. Public learning resources, templates, tutorials, samples, and labs are otherwise marked REVIEW-FOR-DELETION.",
  "",
  `Summary: total forks reviewed: ${counts.total}. KEEP-EXPLICIT: ${counts.keep}. REVIEW-FOR-DELETION: ${counts.review}. MANUAL-NAME-AMBIGUITY-CHECK: ${counts.manual}.`,
  "",
  "## KEEP-EXPLICIT",
  "",
  `Count: ${counts.keep}`,
  "",
  `| ${headers.join(" | ")} |`,
  `| ${headers.map(() => "---").join(" | ")} |`,
  ...groups["forks-to-keep-explicit.csv"].map((row) => `| ${headers.map((header) => String(row[header]).replaceAll("|", "\\|").replace(/\s+/g, " ").trim()).join(" | ")} |`),
  "",
  "## MANUAL-NAME-AMBIGUITY-CHECK",
  "",
  `Count: ${counts.manual}`,
  "",
  `| ${headers.join(" | ")} |`,
  `| ${headers.map(() => "---").join(" | ")} |`,
  ...groups["manual-name-ambiguity-check.csv"].map((row) => `| ${headers.map((header) => String(row[header]).replaceAll("|", "\\|").replace(/\s+/g, " ").trim()).join(" | ")} |`),
  "",
  "## REVIEW-FOR-DELETION",
  "",
  `Count: ${counts.review}`,
  "",
  `| ${headers.join(" | ")} |`,
  `| ${headers.map(() => "---").join(" | ")} |`,
  ...groups["forks-to-review-for-deletion.csv"].map((row) => `| ${headers.map((header) => String(row[header]).replaceAll("|", "\\|").replace(/\s+/g, " ").trim()).join(" | ")} |`),
  "",
].join("\n");

fs.writeFileSync(path.join(outDir, "keep-only-explicit-forks.md"), md);
console.log(JSON.stringify(counts, null, 2));
