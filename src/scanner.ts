import { rules, placeholderDenylist, SecretRule, Severity } from "./rules";
import { findHighEntropyStrings, shannonEntropy } from "./entropy";
import { SecretLoopConfig, defaultConfig, fingerprint } from "./config";

export type ConfidenceTier = "verified-live" | "format-match" | "entropy-heuristic";

/**
 * Whether a credential currently works. `unknown` is a real answer, not a
 * missing one — and it is the common case, since most rules have no verifier
 * and verification is opt-in. Unknown never means safe.
 */
export type LivenessStatus = "live" | "dead" | "unknown";

/**
 * Why liveness could not be determined. These share an outcome but not a
 * remedy, which is the whole reason to keep them apart:
 *
 * - `network`               — the provider was never reached. Fix egress.
 * - `provider-refused`      — a 403. A live-but-scoped credential and a revoked
 *                             one are indistinguishable here, so someone has to
 *                             go look at this one.
 * - `provider-unavailable`  — 429 or 5xx. Retry later; says nothing about the
 *                             credential.
 * - `missing-pair`          — the check needs a second credential that is not
 *                             nearby (an AWS access key with no secret key).
 * - `no-verifier`           — nothing supports checking this rule at all.
 */
export type UnknownReason =
  | "network"
  | "provider-refused"
  | "provider-unavailable"
  | "missing-pair"
  | "no-verifier";

export interface Finding {
  ruleId: string;
  description: string;
  value: string;
  startIndex: number;
  endIndex: number;
  confidence: ConfidenceTier;
  severity: Severity;
  /** 1-based line number of the match within the scanned text. */
  line: number;
  /** Liveness, once a verification pass has run. Undefined = not yet checked. */
  verifyStatus?: LivenessStatus;
  /** Why liveness is unknown. Set only when verifyStatus is "unknown". */
  verifyReason?: UnknownReason;
  /**
   * @deprecated Mirrors verifyStatus for consumers not yet migrated. A boolean
   * cannot express "unknown", which is exactly the distinction that made a 403
   * read as a revocation. Removed once report.ts and cli.ts are on verifyStatus.
   */
  verified?: boolean;
  /** Human-readable verification detail, if verification ran. */
  verifyDetail?: string;
  /** Path of the file this came from, when scanning files rather than raw text. */
  file?: string;
  /** Commit SHA, when the finding came from a git history scan. */
  commit?: string;
  /** Stable identity for baselining. Present when `file` is known. */
  fingerprint?: string;
}

export interface ScanOptions {
  config?: SecretLoopConfig;
  /** Repo-relative path, used for fingerprints and reporting. */
  filePath?: string;
  /** Commit SHA when scanning history. */
  commit?: string;
}

/**
 * Accepts either a bare entropy threshold (back-compat with the original
 * two-arg form) or a full options object.
 */
export function scanText(text: string, optionsOrThreshold?: ScanOptions | number): Finding[] {
  const options: ScanOptions =
    typeof optionsOrThreshold === "number"
      ? { config: { ...defaultConfig, entropyThreshold: optionsOrThreshold } }
      : optionsOrThreshold ?? {};
  const config = options.config ?? defaultConfig;

  const lowerText = text.toLowerCase();
  const lineStarts = computeLineStarts(text);
  const ignoredLines = collectIgnoredLines(text);

  const findings: Finding[] = [];
  const excluded = new Set(config.excludeRules);
  const allowValueRegexes = config.allowValues.map((s) => new RegExp(s));

  for (const rule of rules) {
    if (excluded.has(rule.id)) continue;
    // Literal prescreen: skipping the regex entirely when no keyword is present
    // is what keeps a 90-rule set as fast on large files as a 12-rule one.
    if (rule.keywords && !rule.keywords.some((k) => lowerText.includes(k.toLowerCase()))) continue;

    const regex = indexedRegex(rule);
    regex.lastIndex = 0;
    let m: IndexedMatch | null;
    while ((m = regex.exec(text) as IndexedMatch | null) !== null) {
      // Guard against zero-length matches causing infinite loops.
      if (m[0].length === 0) {
        regex.lastIndex++;
        continue;
      }
      const value = rule.fullMatch ? m[0] : m[1];
      if (!value) continue;
      if (!passesFilters(value, rule, allowValueRegexes)) continue;

      const startIndex = rule.fullMatch ? m.index : captureStart(m, value);
      const line = lineOf(startIndex, lineStarts);
      if (ignoredLines.has(line)) continue;

      findings.push(
        buildFinding({
          ruleId: rule.id,
          description: rule.description,
          value,
          startIndex,
          line,
          confidence: "format-match",
          severity: rule.severity,
          options,
        })
      );
    }
  }

  if (config.entropyPassEnabled && !excluded.has("generic-high-entropy")) {
    for (const hit of findHighEntropyStrings(text, config.entropyThreshold)) {
      if (isPlaceholder(hit.value)) continue;
      if (allowValueRegexes.some((r) => r.test(hit.value))) continue;
      // Skip if this span overlaps a rule-based finding already reported.
      const overlaps = findings.some(
        (f) => hit.index < f.endIndex && hit.index + hit.value.length > f.startIndex
      );
      if (overlaps) continue;

      const line = lineOf(hit.index, lineStarts);
      if (ignoredLines.has(line)) continue;

      findings.push(
        buildFinding({
          ruleId: "generic-high-entropy",
          description: `High-entropy string (entropy ${hit.entropy.toFixed(2)})`,
          value: hit.value,
          startIndex: hit.index,
          line,
          confidence: "entropy-heuristic",
          severity: "medium",
          options,
        })
      );
    }
  }

  return findings.sort((a, b) => a.startIndex - b.startIndex);
}

/**
 * `RegExpExecArray` plus the capture-group offsets the `d` flag adds. Declared
 * here rather than raising the project's `lib` to ES2022 for one property.
 */
type IndexedMatch = RegExpExecArray & {
  indices?: Array<[number, number] | undefined>;
};

const indexedRegexes = new Map<string, RegExp>();

/**
 * A rule's regex, cloned once with the `d` flag so the exact offset of the
 * capture group is available. Cloning here rather than declaring `d` on all 103
 * literals keeps the guarantee in one place — a rule added without the flag
 * can't silently reintroduce the offset bug below.
 */
function indexedRegex(rule: SecretRule): RegExp {
  let regex = indexedRegexes.get(rule.id);
  if (!regex) {
    const flags = rule.regex.flags.includes("d") ? rule.regex.flags : rule.regex.flags + "d";
    regex = new RegExp(rule.regex.source, flags);
    indexedRegexes.set(rule.id, regex);
  }
  return regex;
}

/**
 * Where the captured secret actually starts in the scanned text.
 *
 * Searching the matched text for the value instead picks the wrong occurrence
 * whenever the credential also appears in the match's trailing context — in
 * `mongodb+srv://app:pw@host/pw_db` that meant reporting the database
 * name. The quick-fixes rewrite this span, so the wrong offset redacted the
 * host and left the password in the file while reporting success.
 */
function captureStart(m: IndexedMatch, value: string): number {
  const captureIndices = m.indices?.[1];
  if (captureIndices) return captureIndices[0];
  // `indexedRegex` guarantees `d`; this only covers a runtime that lacks it.
  return m.index + m[0].lastIndexOf(value);
}

function buildFinding(input: {
  ruleId: string;
  description: string;
  value: string;
  startIndex: number;
  line: number;
  confidence: ConfidenceTier;
  severity: Severity;
  options: ScanOptions;
}): Finding {
  const { options } = input;
  return {
    ruleId: input.ruleId,
    description: input.description,
    value: input.value,
    startIndex: input.startIndex,
    endIndex: input.startIndex + input.value.length,
    confidence: input.confidence,
    severity: input.severity,
    line: input.line,
    file: options.filePath,
    commit: options.commit,
    fingerprint: options.filePath
      ? fingerprint(options.filePath, input.ruleId, input.value)
      : undefined,
  };
}

function passesFilters(value: string, rule: SecretRule, allowValues: RegExp[]): boolean {
  if (isPlaceholder(value)) return false;
  if (rule.allowlist?.some((r) => r.test(value))) return false;
  if (allowValues.some((r) => r.test(value))) return false;
  if (rule.entropy !== undefined && shannonEntropy(value) < rule.entropy) return false;
  return true;
}

function isPlaceholder(value: string): boolean {
  const lower = value.toLowerCase();
  if (placeholderDenylist.has(lower)) return true;
  // Repeated character strings (e.g. "aaaaaaaaaaaa") are never real secrets.
  if (/^(.)\1+$/.test(value)) return true;
  return false;
}

/**
 * Honors `secretloop:allow` / `secretloop-ignore` on the matching line or the
 * line directly above it.
 *
 * Two older spellings stay valid on purpose: `secretguard:allow` (this tool's
 * pre-rebrand directive) and `gitleaks:allow`. Suppression annotations live in
 * the user's own source files, so dropping either spelling would silently
 * re-report findings a team had already reviewed and dismissed — across every
 * annotated line at once.
 */
const IGNORE_DIRECTIVE = /(?:secret(?:loop|guard)[:-](?:allow|ignore)|gitleaks:allow)/i;

function collectIgnoredLines(text: string): Set<number> {
  const ignored = new Set<number>();
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    if (!IGNORE_DIRECTIVE.test(lines[i])) continue;
    ignored.add(i + 1); // the annotated line itself
    ignored.add(i + 2); // and the line below, for above-the-line annotations
  }
  return ignored;
}

function computeLineStarts(text: string): number[] {
  const starts = [0];
  for (let i = 0; i < text.length; i++) {
    if (text.charCodeAt(i) === 10) starts.push(i + 1);
  }
  return starts;
}

/** Binary search for the 1-based line containing a character offset. */
export function lineOf(index: number, lineStarts: number[]): number {
  let lo = 0;
  let hi = lineStarts.length - 1;
  while (lo < hi) {
    const mid = Math.ceil((lo + hi) / 2);
    if (lineStarts[mid] <= index) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}

/** Masks a secret for display in logs and reports. */
export function redactValue(value: string): string {
  if (value.length <= 8) return "*".repeat(value.length);
  return `${value.slice(0, 4)}${"*".repeat(Math.min(value.length - 8, 20))}${value.slice(-4)}`;
}
