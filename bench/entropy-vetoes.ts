/**
 * Corpus measurement for the 0.1.4 generic-high-entropy vetoes.
 *
 *   npx ts-node --transpile-only bench/entropy-vetoes.ts
 *
 * Answers one question: how many REALISTIC credentials would each veto throw
 * away? A precision fix that also removes a credential is not a fix, and the
 * only defensible way to know is to measure before enabling.
 *
 * THE CORPUS is the one 0.1.3 used for the post-prefix entropy floor,
 * regenerated here from the same seeded generator so the number is re-runnable
 * rather than quoted from a session that no longer exists. 140,000 realistic
 * samples across eight fixed-prefix token families, at both the documented
 * length and the shortest length the rule accepts, plus a rejection-sampled
 * low-entropy tail -- the population an over-tight filter eats first. The
 * remaining buckets are diagnostics: deliberately structured shapes, kept so a
 * veto that rejects nothing anywhere shows up as inert rather than as safe.
 *
 * TWO ADDITIONS for 0.1.4, both declared rather than folded into the total:
 *
 *   hex-32 / hex-64   The 0.1.3 corpus carries no bare hex -- its hex stress
 *                     bucket is prefixed and drawn at floor length. A 16-symbol
 *                     alphabet is exactly where sequential pairs arise by
 *                     chance, so the ordered-run veto has to be shown against
 *                     one. Reported separately; not counted as realistic.
 *
 * The predicates under test are imported from src/entropy.ts rather than copied,
 * so this file cannot drift away from what ships. The first run of each was made
 * with the predicate inline and the production code untouched; the numbers were
 * identical.
 */
import { hasOrderedRun, orderedRunStats } from "../src/entropy";

const SEED = 20260831;
let s = SEED;
function rand(): number {
  // xorshift32 -- deterministic, no dependency, so a re-run reproduces the
  // corpus byte for byte.
  s ^= s << 13;
  s ^= s >>> 17;
  s ^= s << 5;
  return Math.abs(s) / 2 ** 31;
}

const ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const B64URL = ALNUM + "_-";
const B64 = ALNUM + "+/=";
const PCT = ALNUM + "%";
const ATLAS = ALNUM + "_-=.";
const GHPAT = ALNUM + "_";
const HEX = "0123456789abcdef";
const LOWER = "abcdefghijklmnopqrstuvwxyz";

/** A uniform draw. The last character is forced alphanumeric so a rule's
 *  trailing \b is satisfied and the measurement is of the floor, not the edge. */
function draw(n: number, alpha: string): string {
  let out = "";
  for (let i = 0; i < n - 1; i++) out += alpha[Math.floor(rand() * alpha.length)];
  return out + ALNUM[Math.floor(rand() * ALNUM.length)];
}
/** One character takes `dom` slots; the rest cycle through `spread` others. */
function lowDiv(total: number, dom: number, spread: number): string {
  const others = ALNUM.slice(1, 1 + spread);
  let out = "A".repeat(dom);
  for (let i = 0; i < total - dom; i++) out += others[i % others.length];
  return out;
}

/** rule -> [prefix, alphabet, documented length, shortest accepted length] */
const RULES: Record<string, [string, string, number, number]> = {
  "twitter-bearer-token": ["A".repeat(21), PCT, 89, 50],
  "facebook-access-token": ["EAA", ALNUM, 180, 90],
  "square-access-token": ["EAAA", B64URL, 96, 59],
  "atlassian-api-token": ["ATATT3x", ATLAS, 185, 100],
  "github-fine-grained-pat": ["github_pat_", GHPAT, 82, 60],
  "jfrog-token": ["AKCp", ALNUM, 120, 60],
  "pypi-token": ["pypi-AgEIcHlwaS5vcmc", B64URL, 150, 50],
  "intercom-token": ["dG9r", B64, 110, 50],
};
const IDS = Object.keys(RULES);

const rows: Array<[string, string]> = [];
const push = (bucket: string, value: string) => rows.push([bucket, value]);

// 1. realistic: uniform over the documented alphabet, both lengths.
for (let i = 0; i < 110000; i++) {
  const [pfx, alpha, docLen, floorLen] = RULES[IDS[i % IDS.length]];
  // Rule and length vary on independent strides; driving both off `i` would
  // give each rule only ever one of the two lengths.
  const atFloor = Math.floor(i / IDS.length) % 2 === 1;
  push(atFloor ? "realistic-floor-length" : "realistic-documented",
       pfx + draw(atFloor ? floorLen : docLen, alpha));
}
for (let i = 0; i < 2000; i++) {
  push("realistic-untouched-branch", "sq0atp-" + draw(22, B64URL));
}
// 2. adversarial-plausible: legitimate draws kept only when they land in the
// least random ~1% of their own distribution.
let kept = 0;
for (let i = 0; kept < 28000 && i < 40_000_000; i++) {
  const [pfx, alpha, , floorLen] = RULES[IDS[i % IDS.length]];
  const v = draw(floorLen, alpha);
  const freq = new Map<string, number>();
  for (const c of v) freq.set(c, (freq.get(c) ?? 0) + 1);
  let h = 0;
  for (const c of freq.values()) {
    const p = c / v.length;
    h -= p * Math.log2(p);
  }
  if (h / Math.log2(Math.min(v.length, alpha.length)) < 0.905) {
    push("adversarial-low-tail", pfx + v);
    kept++;
  }
}
// 3. diagnostics: structured shapes a veto SHOULD reject.
for (let i = 0; i < 10000; i++) {
  push("boundary", RULES[IDS[i % IDS.length]][0] + lowDiv(60 + (i % 60), 5 + (i % 45), 20 + (i % 25)));
}
for (let i = 0; i < 50000; i++) {
  const pfx = RULES[IDS[i % IDS.length]][0];
  const k = i % 4;
  let v: string;
  if (k === 0) v = "A".repeat(200) + "g" + "A".repeat(53) + "Q"; // assembly padding
  else if (k === 1) v = lowDiv(90, 45, 29); // base64 of a mostly-zero blob
  else if (k === 2) v = ("AB".repeat(60) + "C").slice(0, 90 + (i % 40)); // two-symbol cycle
  else v = "A".repeat(60 + (i % 60)) + ALNUM.slice(0, 1 + (i % 6)); // near-homogeneous
  push(`fp-shape-${k}`, pfx + v);
}
// 4. sub-alphabet stress, reported separately.
for (let i = 0; i < 6000; i++) {
  const [pfx, , , floorLen] = RULES[IDS[i % IDS.length]];
  const isHex = Math.floor(i / IDS.length) % 2 === 0;
  push(isHex ? "stress-hex" : "stress-lowercase", pfx + draw(floorLen, isHex ? HEX : LOWER));
}
// 5. bare hex, added in 0.1.4. See the header.
for (let i = 0; i < 20000; i++) push("hex-32", draw(32, HEX));
for (let i = 0; i < 20000; i++) push("hex-64", draw(64, HEX));

// ---------------------------------------------------------------- predicates

/**
 * N7b, still proposed at the commit that introduced this file: a candidate is
 * path-shaped only when it carries at least two separators, every segment is
 * letters with no digits, and at least one segment has a lowercase-to-uppercase
 * transition. Replaced by the production predicate when the veto lands.
 */
function isIdentifierPath(value: string): boolean {
  const segments = value.split("/");
  if (segments.length < 3) return false;
  if (!segments.every((seg) => /^[A-Za-z]+$/.test(seg))) return false;
  return segments.some((seg) => /[a-z][A-Z]/.test(seg));
}

// ------------------------------------------------------------------ scoring

/** The buckets that stand for credentials a user would be sorry to lose. */
const REALISTIC = new Set([
  "realistic-documented",
  "realistic-floor-length",
  "realistic-untouched-branch",
  "adversarial-low-tail",
]);

interface Tally {
  n: number;
  byRun: number;
  byFraction: number;
  byEither: number;
  twoSlashes: number;
  pathShaped: number;
  offenders: string[];
}
const tally = new Map<string, Tally>();

for (const [bucket, value] of rows) {
  let t = tally.get(bucket);
  if (!t) {
    t = { n: 0, byRun: 0, byFraction: 0, byEither: 0, twoSlashes: 0, pathShaped: 0, offenders: [] };
    tally.set(bucket, t);
  }
  t.n++;
  const stats = orderedRunStats(value);
  if (stats.longestRun >= 6) t.byRun++;
  if (stats.sequentialFraction >= 0.4) t.byFraction++;
  if (hasOrderedRun(value)) {
    t.byEither++;
    if (t.offenders.length < 5) {
      t.offenders.push(
        `N7a run=${stats.longestRun} frac=${stats.sequentialFraction.toFixed(4)} ${value}`
      );
    }
  }
  if ((value.match(/\//g) ?? []).length >= 2) t.twoSlashes++;
  if (isIdentifierPath(value)) {
    t.pathShaped++;
    if (t.offenders.length < 5) t.offenders.push(`N7b ${value}`);
  }
}

const pct = (part: number, whole: number) => ((part / whole) * 100).toFixed(4) + "%";

console.log(`seed=${SEED}  rows=${rows.length}`);
console.log(
  "bucket                          n   run>=6  frac>=.40   N7a any   >=2 '/'  N7b path"
);
const totals: Tally = {
  n: 0, byRun: 0, byFraction: 0, byEither: 0, twoSlashes: 0, pathShaped: 0, offenders: [],
};
for (const [bucket, t] of [...tally].sort()) {
  console.log(
    `${bucket.padEnd(27)}${String(t.n).padStart(6)}${String(t.byRun).padStart(9)}` +
      `${String(t.byFraction).padStart(11)}${String(t.byEither).padStart(10)}` +
      `${String(t.twoSlashes).padStart(10)}${String(t.pathShaped).padStart(10)}`
  );
  if (!REALISTIC.has(bucket)) continue;
  totals.n += t.n;
  totals.byRun += t.byRun;
  totals.byFraction += t.byFraction;
  totals.byEither += t.byEither;
  totals.twoSlashes += t.twoSlashes;
  totals.pathShaped += t.pathShaped;
}

console.log(`\nREALISTIC TOKENS  n=${totals.n}`);
console.log(`  Fix 1 (N7a)  longest_run >= 6        ${totals.byRun}  ${pct(totals.byRun, totals.n)}`);
console.log(`  Fix 1 (N7a)  seq_fraction >= 0.40    ${totals.byFraction}  ${pct(totals.byFraction, totals.n)}`);
console.log(`  Fix 1 (N7a)  rejected, loss          ${totals.byEither}  ${pct(totals.byEither, totals.n)}`);
console.log(`  Fix 2 (N7b)  samples with >= 2 '/'   ${totals.twoSlashes}  ${pct(totals.twoSlashes, totals.n)}`);
console.log(`  Fix 2 (N7b)  rejected, loss          ${totals.pathShaped}  ${pct(totals.pathShaped, totals.n)}`);

const offenders = [...tally].filter(([b]) => REALISTIC.has(b) && tally.get(b)!.offenders.length > 0);
if (offenders.length === 0) console.log("\nNo realistic sample was rejected by either veto.");
for (const [bucket, t] of offenders) for (const line of t.offenders) console.log(`  ${bucket}: ${line}`);

console.log("\nDIAGNOSTIC BUCKETS (not counted above)");
for (const [bucket, t] of [...tally].sort()) {
  if (REALISTIC.has(bucket)) continue;
  console.log(`  ${bucket.padEnd(20)} N7a ${String(t.byEither).padStart(6)}/${t.n}  N7b ${t.pathShaped}/${t.n}`);
}
