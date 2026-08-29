import {
  rules,
  placeholderDenylist,
  isDocumentationSample,
  genericRuleIds,
  SecretRule,
  Severity,
} from "./rules";
import { findHighEntropyStrings, shannonEntropy } from "./entropy";
import {
  SecretLoopConfig,
  defaultConfig,
  createFingerprint,
  FingerprintStrategy,
  isFixturePath,
} from "./config";

/**
 * The entropy pass's rule id.
 *
 * Named because it is NOT in rules.ts: the entropy pass synthesises findings
 * rather than matching a SecretRule, so `genericRuleIds` -- built from
 * rules.filter(r => r.generic) -- does not contain it. Anything reasoning about
 * "the generic tier" that consults genericRuleIds alone covers half of it, which
 * is exactly how the fixture suppression first shipped suppressing
 * generic-api-key-assignment and nothing else.
 */
export const ENTROPY_RULE_ID = "generic-high-entropy";

/** Both halves of the generic tier: the shape rules and the entropy pass. */
export function isGenericTier(ruleId: string): boolean {
  return ruleId === ENTROPY_RULE_ID || genericRuleIds.has(ruleId);
}

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
  /** Human-readable verification detail, if verification ran. */
  verifyDetail?: string;
  /** Path of the file this came from, when scanning files rather than raw text. */
  file?: string;
  /** Commit SHA, when the finding came from a git history scan. */
  commit?: string;
  /**
   * Other rules that matched this same span and yielded to this one.
   *
   * Recorded rather than discarded: two detectors agreeing is evidence, and a
   * silent drop leaves no way to tell merging from a rule that failed to fire.
   */
  alsoMatched?: string[];
  /** Stable identity for baselining. Present when `file` is known. */
  fingerprint?: string;
  /** How that identity was derived. See FingerprintStrategy. */
  fingerprintStrategy?: FingerprintStrategy;
  /**
   * Span of the whole regex match, as opposed to startIndex/endIndex which span
   * only the captured secret. The match is the semantic unit a context
   * fingerprint is built from: for these rules it pins scheme, user, host and
   * path while excluding anything else on the line.
   */
  matchStart?: number;
  matchEnd?: number;
}

export interface ScanOptions {
  config?: SecretLoopConfig;
  /**
   * Called once per finding dropped by an inline `secretloop:allow` /
   * `gitleaks:allow` directive.
   *
   * A suppression is a deliberate choice a human made, but a report that never
   * mentions it reads exactly like a scan that had nothing to suppress. The
   * count is disclosed; which findings, and whether they were right to
   * suppress, is not this layer's business.
   *
   * Counted by distinct span, not by candidate. A suppressed rule match never
   * enters `findings`, so the entropy pass's overlap check does not fire and
   * the same secret is offered a second time — counting naively reported two
   * suppressions for one annotated credential, which is an overstatement in a
   * disclosure whose whole purpose is not to overstate.
   */
  onSuppressed?: (count: number) => void;
  /**
   * Called with the number of generic-tier findings dropped because this file
   * sits in a test, fixture or example path. Named provider rules are never
   * dropped this way.
   */
  onFixtureSuppressed?: (count: number) => void;
  /**
   * Honour inline `secretloop:allow` / `gitleaks:allow` directives.
   *
   * Default true, which is every scanning caller: the working tree, the staged
   * set and git history all read a repository, and a directive there is a
   * triage decision a human made about that repository.
   *
   * `secretloop mask` and the editor's clipboard command pass false, because a
   * stream someone piped through a scrubber is not that repository's findings.
   * Honouring it there put a live credential on stdout under a summary reading
   * "masked 0 finding(s)" -- a suppressed match never enters `findings`, so
   * maskFindings had nothing to redact and nothing to count. The annotation
   * exists precisely because the value beside it is real, which is what makes
   * this the wrong default for a transform.
   */
  honorInlineDirectives?: boolean;
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
  // Collected, or deliberately empty. One site rather than a check at each of
  // the two places `ignoredLines` is read: a guard that has to be repeated is a
  // guard that can be half-applied, which is exactly how the fixture
  // suppression first shipped covering one half of the generic tier.
  const ignoredLines =
    options.honorInlineDirectives === false ? NO_IGNORED_LINES : collectIgnoredLines(text);
  const suppressedSpans = new Set<number>();

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
      if (ignoredLines.has(line)) {
        suppressedSpans.add(startIndex);
        continue;
      }

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
          matchStart: m.index,
          matchEnd: m.index + m[0].length,
          fingerprintStrategy: strategyFor(rule, m, startIndex),
        })
      );
    }
  }

  const merged = mergeGenericMatches(findings);
  findings.length = 0;
  findings.push(...merged);

  if (config.entropyPassEnabled && !excluded.has(ENTROPY_RULE_ID)) {
    for (const hit of findHighEntropyStrings(text, config.entropyThreshold)) {
      if (isPlaceholder(hit.value)) continue;
      // A published sample has the randomness of a real key, so the named rules
      // dropping it only moves the report down a tier unless this does too.
      if (isDocumentationSample(hit.value)) continue;
      if (allowValueRegexes.some((r) => r.test(hit.value))) continue;
      // Skip if this span overlaps a rule-based finding already reported.
      const overlaps = findings.some(
        (f) => hit.index < f.endIndex && hit.index + hit.value.length > f.startIndex
      );
      if (overlaps) continue;

      const line = lineOf(hit.index, lineStarts);
      if (ignoredLines.has(line)) {
        suppressedSpans.add(hit.index);
        continue;
      }

      findings.push(
        buildFinding({
          ruleId: ENTROPY_RULE_ID,
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

  if (suppressedSpans.size > 0) options.onSuppressed?.(suppressedSpans.size);

  // Generic-tier findings in test and fixture paths, dropped and counted.
  //
  // Applied here rather than in the walker because this is the only layer that
  // knows both which rule matched and where the file is -- and because every
  // caller reaches the scanner through it, so the working tree, the staged set
  // and git history behave the same without three copies of the rule.
  //
  // Named rules are exempt by construction: a `ghp_` committed to a test file
  // is a leaked credential, and the noise this addresses is entirely generic.
  let fixtureSuppressed = 0;
  if (!config.includeFixtures && options.filePath && isFixturePath(options.filePath)) {
    for (let i = findings.length - 1; i >= 0; i--) {
      if (isGenericTier(findings[i].ruleId)) {
        findings.splice(i, 1);
        fixtureSuppressed++;
      }
    }
    if (fixtureSuppressed > 0) options.onFixtureSuppressed?.(fixtureSuppressed);
  }

  const sorted = findings.sort((a, b) => a.startIndex - b.startIndex);
  if (options.filePath) assignFingerprints(sorted, text, options.filePath);
  return sorted;
}

/**
 * Which fingerprint strategy a match should use.
 *
 * Most rules declare it outright. generic-api-key-assignment cannot: its
 * alternation over api_key|…|passwd|password is a single non-capturing group,
 * so the rule matches both provider tokens and human passwords. Splitting it in
 * two would change rule IDs, invalidating every baseline entry and every
 * excludeRules entry in every user config — for information already sitting in
 * the match. The `d` flag gives the captured value's offset, and everything
 * before it in the match is the keyword.
 */
function strategyFor(rule: SecretRule, m: RegExpExecArray, valueStart: number): FingerprintStrategy {
  if (rule.fingerprintStrategy !== "keyword") return rule.fingerprintStrategy ?? "value";
  const keyword = m[0].slice(0, valueStart - m.index).match(/^[A-Za-z_.\-]+/)?.[0] ?? "";
  return /passw(or)?d/i.test(keyword) ? "context" : "value";
}

/**
 * Text of a region with every known secret in it replaced.
 *
 * Redacting only the finding being fingerprinted would leave any other
 * credential in the region in plaintext — and the fingerprint is committed. A
 * line like `DB=postgres://svc:pw@h/db  # legacy: ghp_…` would put a live
 * GitHub token straight into the baseline: a fingerprinting fix with a worse
 * leak than the bug it fixes.
 *
 * Exported so a test can assert directly on what gets hashed.
 */
export function secretFreeContext(
  text: string,
  start: number,
  end: number,
  findings: Finding[]
): string {
  const spans = findings
    .filter((f) => f.startIndex < end && f.endIndex > start)
    .map((f) => [Math.max(f.startIndex, start), Math.min(f.endIndex, end)] as const)
    .sort((a, b) => b[0] - a[0]); // right to left, so earlier offsets stay valid

  let region = text.slice(start, end);
  for (const [from, to] of spans) {
    region = region.slice(0, from - start) + "[REDACTED]" + region.slice(to - start);
  }
  // Unrelated formatting must not change identity.
  return region.replace(/\s+/g, " ").trim();
}

/** The line containing an offset, as a [start, end) span. */
function lineSpan(text: string, index: number): readonly [number, number] {
  const start = text.lastIndexOf("\n", index - 1) + 1;
  const nl = text.indexOf("\n", index);
  return [start, nl === -1 ? text.length : nl];
}

/**
 * Assigns every finding its baseline identity.
 *
 * Context fingerprints escalate only on collision, deterministically: the match
 * first, then the whole line, then an ordinal among findings that remain
 * indistinguishable. `password = "…"` redacts to the same text wherever it
 * appears, so without the last tier two passwords in one file would share a
 * fingerprint and baselining one would silence the other.
 */
function assignFingerprints(findings: Finding[], text: string, filePath: string): void {
  const assign = (f: Finding, context?: string) => {
    f.fingerprint = createFingerprint({
      filePath,
      ruleId: f.ruleId,
      strategy: f.fingerprintStrategy ?? "value",
      value: f.value,
      context,
    });
  };

  for (const f of findings) {
    if ((f.fingerprintStrategy ?? "value") !== "context") {
      assign(f);
      continue;
    }
    const start = f.matchStart ?? f.startIndex;
    const end = f.matchEnd ?? f.endIndex;
    assign(f, secretFreeContext(text, start, end, findings));
  }

  escalateCollisions(findings, text, filePath, (f) => {
    const [start, end] = lineSpan(text, f.startIndex);
    return secretFreeContext(text, start, end, findings);
  });
  // Last tier, and a known limitation rather than an oversight.
  //
  // For generic-api-key-assignment the line IS the match, and redaction erases
  // the only thing telling two of them apart: `password = "[REDACTED]"` is
  // identical however many times it appears. With the value excluded by
  // construction and the line number excluded by design, an ordinal among
  // otherwise-identical peers is the only distinguishing material left.
  //
  // The cost: deleting the first of two identical password lines shifts the
  // second's ordinal, so a previously accepted finding is reported again. That
  // is a re-triage, not a leak — the alternative was letting one baseline entry
  // silence a different password in the same file.
  escalateCollisions(findings, text, filePath, (f, ordinal) => {
    const [start, end] = lineSpan(text, f.startIndex);
    return `${secretFreeContext(text, start, end, findings)}#${ordinal}`;
  });
}

/** Re-derives context-strategy fingerprints that are still not unique. */
function escalateCollisions(
  findings: Finding[],
  text: string,
  filePath: string,
  contextOf: (finding: Finding, ordinal: number) => string
): void {
  const byFingerprint = new Map<string, Finding[]>();
  for (const f of findings) {
    if ((f.fingerprintStrategy ?? "value") !== "context" || !f.fingerprint) continue;
    const bucket = byFingerprint.get(f.fingerprint);
    if (bucket) bucket.push(f);
    else byFingerprint.set(f.fingerprint, [f]);
  }

  for (const clashing of byFingerprint.values()) {
    if (clashing.length < 2) continue;
    clashing.forEach((f, ordinal) => {
      f.fingerprint = createFingerprint({
        filePath,
        ruleId: f.ruleId,
        strategy: "context",
        value: f.value,
        context: contextOf(f, ordinal),
      });
    });
  }
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

/**
 * Collapses a shape-matched finding into the named finding covering the same
 * span, recording which rule yielded.
 *
 * Two rules matching one secret produced two diagnostics on one range, two
 * SARIF alerts and two baseline entries. Only the generic rule ever yields —
 * named rules that overlap each other are left alone, because that is a
 * rule-design bug better fixed with an allowlist than buried under a tiebreak.
 *
 * The survivor keeps its own fingerprint, so a baseline written before this
 * change still matches: identity is path:ruleId:value, none of which merging
 * touches.
 */
function mergeGenericMatches(findings: Finding[]): Finding[] {
  // Always a fresh array. Returning the same reference broke the caller, which
  // empties `findings` before re-filling it from the result.
  const generic = findings.filter((f) => genericRuleIds.has(f.ruleId));
  if (generic.length === 0) return findings.slice();

  const named = findings.filter((f) => !genericRuleIds.has(f.ruleId));
  const absorbed = new Set<Finding>();

  for (const shape of generic) {
    for (const specific of named) {
      if (shape.startIndex >= specific.endIndex || specific.startIndex >= shape.endIndex) continue;
      const already = (specific.alsoMatched ??= []);
      if (!already.includes(shape.ruleId)) already.push(shape.ruleId);
      absorbed.add(shape);
    }
  }

  return findings.filter((f) => !absorbed.has(f));
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
  matchStart?: number;
  matchEnd?: number;
  fingerprintStrategy?: FingerprintStrategy;
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
    matchStart: input.matchStart,
    matchEnd: input.matchEnd,
    fingerprintStrategy: input.fingerprintStrategy ?? "value",
    // Assigned in a second pass: a context fingerprint must redact every
    // finding in its region, which is not known until the scan is complete.
    fingerprint: undefined,
  };
}

function passesFilters(value: string, rule: SecretRule, allowValues: RegExp[]): boolean {
  if (isPlaceholder(value)) return false;
  if (rule.allowlist?.some((r) => r.test(value))) return false;
  if (allowValues.some((r) => r.test(value))) return false;
  if (rule.entropy !== undefined && shannonEntropy(value) < rule.entropy) return false;
  return true;
}

/**
 * A template or shell expansion: `${gen(20)}`, `${DB_PASSWORD}`, `$API_KEY`.
 *
 * A placeholder by construction — it is the code that produces a value, not the
 * value. Anchored to the start so a password that merely contains a dollar sign
 * still reports.
 */
const EXPANSION = /^\$\{|^\$[A-Za-z_]/;

function isPlaceholder(value: string): boolean {
  const lower = value.toLowerCase();
  if (placeholderDenylist.has(lower)) return true;
  // Repeated character strings (e.g. "aaaaaaaaaaaa") are never real secrets.
  if (/^(.)\1+$/.test(value)) return true;
  // Shared rather than rule-scoped: generic-api-key-assignment already carried
  // this guard in its own allowlist, so the class was recognised but fixed in
  // one place. The three rules whose captures accept arbitrary text — snowflake,
  // db-connection-string, http-basic-auth-url — reported `${gen(20)}` as a
  // credential. Constrained-alphabet captures exclude $ { } and never could.
  if (EXPANSION.test(value)) return true;
  return false;
}

/**
 * Honors `secretloop:allow` / `secretloop-ignore` on the matching line or the
 * line directly above it.
 *
 * `gitleaks:allow` stays valid on purpose. gitleaks shipped and has a large
 * installed base, so a repository already annotated for it needs no
 * re-annotation to adopt SecretLoop — and a suppression annotation that stops
 * being honoured silently re-reports a finding someone deliberately dismissed.
 */
const IGNORE_DIRECTIVE = /(?:secretloop[:-](?:allow|ignore)|gitleaks:allow)/i;

/** Shared empty set for `honorInlineDirectives: false`. Never written to. */
const NO_IGNORED_LINES: ReadonlySet<number> = new Set<number>();

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

/**
 * Masks a secret for display in logs and reports.
 *
 * Three tiers, because "first four and last four" is a fraction, not a
 * constant. On a 9-character value it revealed eight of nine characters, and a
 * 10-character value eight of ten — in CI logs, in JSON, and in SARIF, with
 * redaction ON. That length range is where human-chosen passwords live, and it
 * is the same material the context-fingerprint strategy already refuses to
 * hash. A display path cannot be looser than the identity path about the same
 * bytes.
 *
 * The prefix survives below 16 characters because recognising a `ghp_` or
 * `sk-` shape is most of what a reader needs from a masked value; the suffix
 * does not, because prefix plus suffix is the pair that reconstructs a short
 * secret.
 */
/**
 * The text with every finding replaced by [REDACTED:<ruleId>].
 *
 * Right to left, so each remaining span's offsets stay valid -- the same reason
 * secretFreeContext works backwards. Sorted here rather than trusting the
 * caller: scanText returns findings sorted by start offset, and a transform
 * that silently corrupts its output if that ever changes is not worth the saved
 * line.
 *
 * Shared by `secretloop mask` and the editor's clipboard command so the two
 * cannot disagree about what masking means.
 */
export function maskFindings(text: string, findings: Finding[]): string {
  return [...findings]
    .sort((a, b) => b.startIndex - a.startIndex)
    .reduce(
      (acc, f) => acc.slice(0, f.startIndex) + `[REDACTED:${f.ruleId}]` + acc.slice(f.endIndex),
      text
    );
}

export function redactValue(value: string): string {
  if (value.length <= 8) return "*".repeat(value.length);
  if (value.length < 16) return `${value.slice(0, 2)}${"*".repeat(value.length - 2)}`;
  return `${value.slice(0, 4)}${"*".repeat(Math.min(value.length - 8, 20))}${value.slice(-4)}`;
}
