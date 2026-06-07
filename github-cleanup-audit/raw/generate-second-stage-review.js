const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");
const input = path.join(root, "forks-to-review.csv");

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

function csvEscape(value) {
  const text = String(value ?? "");
  return /[",\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

function normalize(row) {
  return [
    row["repo name"],
    row["repo URL"],
    row["upstream/parent if available"],
    row["last updated date"],
    row["reason it was originally marked REVIEW"],
    row["new second-stage category"],
    row["deletion confidence from 1 to 5"],
    row["short reason"],
  ];
}

const rows = parseCsv(fs.readFileSync(input, "utf8"));
const headers = rows[0];
const records = rows.slice(1).map((row) => Object.fromEntries(headers.map((header, index) => [header, row[index] || ""])));

const learningPattern = /\b(mslearn|microsoftlearning|microsoft learn|learn|course|guide|training|bootcamp|workshop|tutorial|lab|labs|certification|exam|skillsboost|copilot|github actions|actions|checkout|setup-node|artifact|cache|runner|starter|clean-code|interviews|academind|az-|dp-|sc-|pl-|ms-|mb-|md-|apl-)\b/i;
const portfolioPattern = /\b(ai|a2a|agent|agents|azureai|openai|dall-e|vision|genai|langchain|diffusers|nanovlm|gan|biggan|vae|pytorch|torch|nltk|gensim|scipy|scikit|machine learning|predictive|forecasting|data|pipeline|fabric|powerbi|processmining|gurobi|optimization|security|cyber|atomic|phish|urlhaus|nhs|ambulance|health|clinical|tnm|attendance|turing|docker|buildx|compose|cli|docs|contribution|open-source|framework|samples|templates)\b/i;

function classify(record) {
  const name = record["repository name"];
  const url = record["repository URL"];
  const upstream = record["upstream/original repository if available"];
  const unique = record["whether there appear to be unique commits or meaningful changes by me"];
  const value = record["whether there are signs of portfolio value, learning value, or contribution value"];
  const originalReason = record["short reason for the recommendation"];
  const haystack = `${name} ${url} ${upstream} ${value} ${originalReason}`.toLowerCase();
  const noUnique = unique.startsWith("No obvious unique commits");
  const noSignal = value === "No clear signal";

  if (learningPattern.test(haystack) || value.includes("learning")) {
    return {
      category: "possible-learning-value",
      confidence: 1,
      reason: "Name, upstream, or original audit signal suggests course, lab, certification, GitHub Actions, or learning/reference value.",
    };
  }

  if (portfolioPattern.test(haystack) || value.includes("portfolio") || value.includes("contribution")) {
    return {
      category: "possible-portfolio-or-contribution-value",
      confidence: 1,
      reason: "Repository or upstream name suggests technical reference, portfolio relevance, domain value, or possible contribution context.",
    };
  }

  return {
    category: "needs-manual-browser-check",
    confidence: noUnique && noSignal ? 3 : 2,
    reason: noUnique && noSignal
      ? "Existing CSV shows no obvious unique commits or value signal, but the source of truth is insufficient to rule out README edits, PR context, or personal reference value."
      : "Existing CSV evidence is not enough to rule out README edits, unique work, PR context, or personal reference value.",
  };
}

const outputRows = records.map((record) => {
  const result = classify(record);
  return {
    "repo name": record["repository name"],
    "repo URL": record["repository URL"],
    "upstream/parent if available": record["upstream/original repository if available"],
    "last updated date": record["last updated date"],
    "reason it was originally marked REVIEW": record["short reason for the recommendation"],
    "new second-stage category": result.category,
    "deletion confidence from 1 to 5": result.confidence,
    "short reason": result.reason,
  };
});

const categories = [
  "likely-safe-to-delete",
  "possible-learning-value",
  "possible-portfolio-or-contribution-value",
  "needs-manual-browser-check",
];

const outHeaders = Object.keys(outputRows[0]);
for (const category of categories) {
  const subset = outputRows.filter((row) => row["new second-stage category"] === category);
  const csv = [
    outHeaders.map(csvEscape).join(","),
    ...subset.map((row) => outHeaders.map((header) => csvEscape(row[header])).join(",")),
    "",
  ].join("\n");
  fs.writeFileSync(path.join(root, `${category}.csv`), csv);
}

const grouped = categories.flatMap((category) => {
  const subset = outputRows.filter((row) => row["new second-stage category"] === category);
  return [
    `## ${category}`,
    "",
    `Count: ${subset.length}`,
    "",
    `| ${outHeaders.join(" | ")} |`,
    `| ${outHeaders.map(() => "---").join(" | ")} |`,
    ...subset.map((row) => `| ${normalize(row).map((value) => String(value).replaceAll("|", "\\|").replace(/\s+/g, " ").trim()).join(" | ")} |`),
    "",
  ];
});

const counts = Object.fromEntries(categories.map((category) => [category, outputRows.filter((row) => row["new second-stage category"] === category).length]));
const markdown = [
  "# Second-Stage Fork Review",
  "",
  `Generated: ${new Date().toISOString()}`,
  "",
  "Source of truth: `github-cleanup-audit/forks-to-review.csv` only.",
  "",
  "No repositories were deleted, archived, renamed, transferred, or modified.",
  "",
  "Deletion confidence uses a 1 to 5 scale. Items with learning, certification, portfolio, contribution, possible unique work, or uncertainty are not placed in `likely-safe-to-delete`.",
  "",
  `Summary: ${outputRows.length} REVIEW repositories processed. likely-safe-to-delete: ${counts["likely-safe-to-delete"]}. possible-learning-value: ${counts["possible-learning-value"]}. possible-portfolio-or-contribution-value: ${counts["possible-portfolio-or-contribution-value"]}. needs-manual-browser-check: ${counts["needs-manual-browser-check"]}.`,
  "",
  ...grouped,
].join("\n");

fs.writeFileSync(path.join(root, "second-stage-review.md"), markdown);
console.log(JSON.stringify({ total: outputRows.length, ...counts }, null, 2));
