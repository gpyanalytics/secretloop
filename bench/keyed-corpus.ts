/**
 * N8 key-context gate — the measurement.
 *
 * Answers two questions over real open-source code, and refuses to answer a
 * third that the data cannot support.
 *
 *   1. What identifiers do this tier's candidates actually sit under?
 *   2. How many of those candidates does the gate suppress?
 *
 * The question it does NOT answer is the one that would justify shipping the
 * gate on by default: what fraction of TRUE POSITIVES it suppresses. That
 * requires knowing the identifiers real secrets are stored under, and no
 * available source gives it. The two real-world proxies bracket it from
 * opposite sides by selection bias — identifiers harvested from a
 * keyword-anchored detector's own hits match the word list 100% of the time by
 * construction, and identifiers harvested from every high-entropy string in
 * real packages match around a tenth of the time because that population is
 * overwhelmingly hashes and resource IDs rather than credentials. A threshold
 * placed anywhere between those two is chosen, not measured, so this file
 * reports a figure and states no verdict.
 *
 * WHAT THE POPULATION IS. Every candidate below is a string this tier would
 * report, in a published SDK or framework, at a pinned commit. The
 * fourteen-repository false-positive study in bench/MULTI-CORPUS.md measured
 * 10,025 of 10,029 findings on this same corpus as false positives, so the
 * suppression fraction here is read as a noise reduction. It is not a
 * precision measurement and the four are not chased: this file counts
 * candidates, not verdicts.
 *
 * The predicates are imported from the shipped source rather than restated, so
 * these numbers cannot drift from what actually runs — the convention
 * bench/entropy-vetoes.ts established for the 0.1.4 vetoes.
 *
 * Corpus identities and commits: bench/keyed-repos.txt. Point CORPUS_ROOT at
 * the clone directory; the default matches the recreate instructions there.
 *
 *   npx ts-node --transpile-only bench/keyed-corpus.ts
 */

import * as fs from "fs";
import * as path from "path";
import {
  findHighEntropyStrings,
  resolveQuotedIdentifier,
  identifierSuggestsSecret,
  splitIdentifierWords,
} from "../src/entropy";
import { defaultConfig } from "../src/config";

const CORPUS_ROOT = process.env.CORPUS_ROOT ?? "/Users/mac/Documents/GPY/n8-corpus-repos";

/**
 * Directories the product never scans, plus build output. Not a re-derivation
 * of the product's exclusion list — this walk is deliberately simple, and any
 * difference makes the denominator larger rather than smaller.
 */
const SKIP_DIR = new Set([
  ".git",
  "node_modules",
  "dist",
  "build",
  "out",
  ".next",
  "vendor",
  "Pods",
]);

const TEXT =
  /\.(js|jsx|ts|tsx|mjs|cjs|json|ya?ml|env|properties|toml|ini|sh|py|rb|go|java|kt|cs|php|dart|md|txt|xml|gradle|plist|conf|cfg)$/i;

/** Matches the product's own default. A file larger than this is not scanned. */
const MAX_BYTES = defaultConfig.maxFileSizeBytes;

interface Row {
  repo: string;
  identifier: string | null;
  quoted: boolean;
  matched: boolean;
}

const rows: Row[] = [];
let filesScanned = 0;

function walk(dir: string, repo: string): void {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!SKIP_DIR.has(entry.name)) walk(full, repo);
      continue;
    }
    if (!TEXT.test(entry.name)) continue;
    let size: number;
    try {
      size = fs.statSync(full).size;
    } catch {
      continue;
    }
    if (size > MAX_BYTES) continue;
    let text: string;
    try {
      text = fs.readFileSync(full, "utf8");
    } catch {
      continue;
    }
    filesScanned++;

    for (const hit of findHighEntropyStrings(text, defaultConfig.entropyThreshold)) {
      // A candidate is quoted when the character before it is a quote — the
      // same condition the gate itself applies, read back off the text rather
      // than re-deriving which pattern produced the hit.
      const quoted = hit.index > 0 && /["'`]/.test(text[hit.index - 1]);
      const identifier = quoted ? resolveQuotedIdentifier(text, hit.index - 1) : null;
      rows.push({
        repo,
        identifier,
        quoted,
        matched: identifier !== null && identifierSuggestsSecret(identifier),
      });
    }
  }
}

for (const repo of fs.readdirSync(CORPUS_ROOT)) {
  const dir = path.join(CORPUS_ROOT, repo);
  let isDir = false;
  try {
    isDir = fs.statSync(dir).isDirectory();
  } catch {
    isDir = false;
  }
  if (isDir) walk(dir, repo);
}

// ------------------------------------------------------------------ reporting

const total = rows.length;
const quoted = rows.filter((r) => r.quoted);
const unquoted = total - quoted.length;
const resolved = quoted.filter((r) => r.identifier !== null);
const unresolved = quoted.length - resolved.length;
const matched = resolved.filter((r) => r.matched);
/** Exactly the gate's condition: quoted, identifier resolved, no word match. */
const suppressed = resolved.filter((r) => !r.matched);

const pct = (n: number, d: number) => (d === 0 ? "n/a" : ((100 * n) / d).toFixed(2) + "%");

console.log("N8 key-context gate — candidate population");
console.log("corpus root      :", CORPUS_ROOT);
console.log("files scanned    :", filesScanned.toLocaleString());
console.log("candidates       :", total.toLocaleString());
console.log("");
console.log("  quoted literals:", quoted.length.toLocaleString(), pct(quoted.length, total));
console.log("    identifier resolved  :", resolved.length.toLocaleString(), pct(resolved.length, total));
console.log("      word-list match    :", matched.length.toLocaleString(), pct(matched.length, total));
console.log("      no match → SUPPRESSED:", suppressed.length.toLocaleString(), pct(suppressed.length, total));
console.log("    no identifier → falls through:", unresolved.toLocaleString(), pct(unresolved, total));
console.log("  unquoted → never gated:", unquoted.toLocaleString(), pct(unquoted, total));
console.log("");
console.log("FP REDUCTION on this population:", pct(suppressed.length, total));
console.log("  (reported, not judged against a threshold — see the header)");

/**
 * The aggregate is concentrated, so it is reported next to the figure it
 * dominates rather than in a footnote. bench/MULTI-CORPUS.md flagged the same
 * hazard for the same reason: two of these repositories are generated-client
 * monorepos whose .json API definitions carry candidates by the thousand, and
 * an aggregate over them is mostly a measurement of one project's code
 * generator. Neither number is the true one — they bound how much the answer
 * depends on corpus composition, which is the honest thing to publish.
 */
const perRepoCounts = [...new Set(rows.map((r) => r.repo))].map((repo) => ({
  repo,
  n: rows.filter((r) => r.repo === repo).length,
  sup: rows.filter((r) => r.repo === repo && r.quoted && r.identifier !== null && !r.matched)
    .length,
}));
const largest = perRepoCounts.reduce((a, b) => (b.n > a.n ? b : a));
const exN = total - largest.n;
const exSup = suppressed.length - largest.sup;
console.log(
  "  largest contributor:",
  largest.repo,
  "—",
  largest.n.toLocaleString(),
  "candidates",
  pct(largest.n, total),
  "of the corpus"
);
console.log("  excluding it:", pct(exSup, exN), `(${exSup.toLocaleString()} of ${exN.toLocaleString()})`);

// Per-repo, because one generated-client monorepo can carry the whole number.
console.log("\nper repository");
const repos = [...new Set(rows.map((r) => r.repo))].sort();
console.log("  repo".padEnd(38), "cands".padStart(7), "suppressed".padStart(12), "rate".padStart(8));
for (const repo of repos) {
  const rs = rows.filter((r) => r.repo === repo);
  const sup = rs.filter((r) => r.quoted && r.identifier !== null && !r.matched).length;
  console.log(
    ("  " + repo).padEnd(38),
    String(rs.length).padStart(7),
    String(sup).padStart(12),
    pct(sup, rs.length).padStart(8)
  );
}

// The distribution itself: what these candidates are actually called.
const freq = new Map<string, { n: number; matched: boolean }>();
for (const r of resolved) {
  const key = r.identifier as string;
  const cur = freq.get(key) ?? { n: 0, matched: r.matched };
  cur.n++;
  freq.set(key, cur);
}
const ranked = [...freq.entries()].sort((a, b) => b[1].n - a[1].n);

console.log("\nidentifier distribution — top 40 of", ranked.length.toLocaleString(), "distinct");
console.log("  count  match  identifier                       words");
for (const [id, info] of ranked.slice(0, 40)) {
  console.log(
    "  " +
      String(info.n).padStart(5) +
      "  " +
      (info.matched ? "OPEN " : "close") +
      "  " +
      id.slice(0, 32).padEnd(33) +
      splitIdentifierWords(id).join("|")
  );
}

const distinctMatched = ranked.filter(([, i]) => i.matched).length;
console.log("\ndistinct identifiers matching the word list:", distinctMatched, "of", ranked.length);
