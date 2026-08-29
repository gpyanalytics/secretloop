import { Finding, UnknownReason, redactValue } from "./scanner";

export type OutputFormat = "text" | "json" | "sarif";

export interface ReportOptions {
  /** Mask secret values in the output. Default true — reports end up in CI logs. */
  redact: boolean;
  /** Repo-relative root used for display paths. */
  root: string;
  /**
   * What was scanned, for the opening line — "31 commits", "412 files".
   * Omitted when the caller has nothing meaningful to say.
   */
  scope?: string;
  /** How many units were covered, for a consumer that wants the number alone. */
  scannedCount?: number;
  /** What those units are: "file", "staged file", "commit". */
  scopeNoun?: string;
}

/**
 * What the report says was covered.
 *
 * Zero is called out rather than left to read as a pass. An excludePaths entry
 * that swallowed the tree, an empty rev-range and a repository with no commits
 * all arrive here, and "Scanned 0 file(s)." is a true sentence that a reader
 * skims as a clean bill of health.
 *
 * Lives here rather than in cli.ts so the extension can say the same sentence
 * without pulling the CLI's entry point into its bundle.
 */
/**
 * Everything a scan skipped or held back, for the scope sentence.
 *
 * An options object rather than positional arguments. It was
 * (count, noun, generatedExcluded, suppressed) and two more clauses were coming;
 * a six-argument call whose middle three are zeros is a call nobody can read,
 * and adding a clause in the wrong position is a silent miscount rather than a
 * type error.
 */
export interface ScopeNotes {
  /** Files skipped by the generated-file group. */
  generatedExcluded?: number;
  /** Findings dropped by an inline secretloop:allow / gitleaks:allow. */
  suppressed?: number;
  /** Files skipped because their realpath is outside the scan root. */
  outsideExcluded?: number;
  /** Generic-tier findings dropped because the file is test/fixture material. */
  fixtureSuppressed?: number;
  /** Files enumerated but skipped for exceeding maxFileSizeBytes. */
  oversizedExcluded?: number;
  /** Files enumerated but skipped as binary, or unreadable at the read. */
  unreadableExcluded?: number;
}

export function describeScope(count: number, noun: string, notes: ScopeNotes = {}): string {
  const {
    generatedExcluded = 0,
    suppressed = 0,
    outsideExcluded = 0,
    fixtureSuppressed = 0,
    oversizedExcluded = 0,
    unreadableExcluded = 0,
  } = notes;
  const base =
    count === 0
      ? `0 ${noun}(s) — nothing was scanned, so this is not a clean result`
      : `${count} ${noun}(s)`;
  // Disclosure, not a footnote. A scan that skipped generated files must not
  // read identically to one that had none to skip — which is the whole reason
  // the count is threaded up from the walker instead of being dropped there.
  let out = base;
  if (generatedExcluded > 0) {
    out +=
      `; ${generatedExcluded} generated file(s) excluded by default ` +
      `(--include-generated to scan them)`;
  }
  // A suppression is a choice someone made on purpose, but a report that never
  // mentions it reads exactly like a scan with nothing to suppress. Appended
  // rather than folded in, so the three-argument form stays byte-identical and
  // the callers pinned against it are unaffected.
  if (suppressed > 0) {
    out += `; ${suppressed} finding(s) suppressed by inline directives`;
  }
  // A scan that silently read through a symlink and out of the directory it was
  // pointed at would be the worst of both: content from outside reported under
  // a path inside, with nothing saying so.
  if (outsideExcluded > 0) {
    out += `; ${outsideExcluded} file(s) excluded (symlinks resolving outside the scan root)`;
  }
  if (fixtureSuppressed > 0) {
    out +=
      `; ${fixtureSuppressed} generic finding(s) suppressed in test/fixture paths ` +
      `(--include-fixtures to report them)`;
  }
  // The last skip that was silent, and the biggest one on a real repository.
  // A file enumerated and then dropped at the read was simply absent from the
  // count, so a tree whose credentials all sit in files over the size cap
  // reported the same sentence as a clean one. Two clauses rather than one
  // because the remedies differ: raising maxFileSizeBytes answers the first and
  // answers nothing about the second.
  if (oversizedExcluded > 0) {
    out +=
      `; ${oversizedExcluded} file(s) not scanned — larger than maxFileSizeBytes ` +
      `(raise it in .secretloop.json to cover them)`;
  }
  if (unreadableExcluded > 0) {
    out += `; ${unreadableExcluded} file(s) not scanned — binary or unreadable`;
  }
  return out;
}

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 } as const;

/**
 * How each unknown reads to someone holding the report. They share an exit code
 * but not a remedy, so the report groups by remedy — "the network is down" and
 * "go look at that credential" are not the same task.
 */
export const UNKNOWN_REASONS: Record<UnknownReason, { label: string; remedy: string }> = {
  network: {
    label: "could not reach the provider",
    remedy: "a connectivity problem, not a verdict on the credential — fix egress and re-run",
  },
  "provider-refused": {
    label: "the provider refused the check",
    remedy:
      "a live-but-scoped credential and a revoked one look identical here — inspect these directly",
  },
  "provider-unavailable": {
    label: "the provider was unavailable",
    remedy: "rate-limited or erroring; retry later",
  },
  "missing-pair": {
    label: "a paired credential was missing",
    remedy: "the check needs a second credential that is not next to this one",
  },
  "no-verifier": {
    label: "no verifier exists for this credential type",
    remedy: "nothing can confirm this one; judge it on format alone",
  },
};

/**
 * Ordering is by what to do next: rotate now, then look into, then judge
 * yourself, then — last, whatever its severity — the one already proven dead.
 */
function livenessRank(f: Finding): number {
  switch (f.verifyStatus) {
    case "live":
      return 0;
    case "unknown":
      return 1;
    case "dead":
      return 3;
    default:
      return 2; // never checked
  }
}

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const av = livenessRank(a);
    const bv = livenessRank(b);
    if (av !== bv) return av - bv;
    const as = SEVERITY_ORDER[a.severity] ?? 9;
    const bs = SEVERITY_ORDER[b.severity] ?? 9;
    if (as !== bs) return as - bs;
    return (a.file ?? "").localeCompare(b.file ?? "") || a.line - b.line;
  });
}

export function render(findings: Finding[], format: OutputFormat, options: ReportOptions): string {
  const sorted = sortFindings(findings);
  switch (format) {
    case "json":
      return renderJson(sorted, options);
    case "sarif":
      return renderSarif(sorted, options);
    default:
      return renderText(sorted, options);
  }
}

function displayValue(f: Finding, redact: boolean): string {
  return redact ? redactValue(f.value) : f.value;
}

function renderText(findings: Finding[], options: ReportOptions): string {
  if (findings.length === 0) {
    // The scope matters most in exactly this branch, and this is where it used
    // to be dropped. "no secrets found" over an enumeration that produced
    // nothing is the difference between looking and not looking, printed as if
    // it were the same sentence. A caller with nothing to say about scope still
    // gets the bare line.
    return options.scope ? `Scanned ${options.scope}. No secrets found.` : "SecretLoop: no secrets found.";
  }

  const live = findings.filter((f) => f.verifyStatus === "live");
  const needsLook = findings.filter((f) => f.verifyStatus === "unknown");
  const unchecked = findings.filter((f) => f.verifyStatus === undefined);
  const dead = findings.filter((f) => f.verifyStatus === "dead");

  // The shape of the result belongs before the detail. On a real repository the
  // trailing summary lands after hundreds of lines, so a reader learns what
  // they are looking at only by scrolling back up.
  // One string, used at both ends. Header and footer are read together — in a
  // terminal, and side by side in any recording — so they must not describe the
  // same four numbers with different words. "needing" also reads correctly for
  // a count of one, which "needs"/"need" cannot both do.
  const counts =
    `${findings.length} finding(s): ${live.length} confirmed live, ` +
    `${needsLook.length} needing a look, ${unchecked.length} unverified, ${dead.length} dead.`;
  const lines: string[] = [options.scope ? `Scanned ${options.scope}. ${counts}` : counts, ""];

  if (live.length > 0) {
    lines.push(`CONFIRMED LIVE (${live.length}) — these credentials currently work. Rotate them.`);
    for (const g of groupByValue(live)) lines.push(...formatGroup(g, options));
    lines.push("");
  }

  if (needsLook.length > 0) {
    lines.push(
      `NEEDS A LOOK (${needsLook.length}) — checked, but liveness could not be determined.`
    );
    // Grouped by remedy: one of these groups is an infrastructure fix and
    // another is a person opening a provider console. Interleaving them buries
    // that distinction, which is the only thing the reader is here for.
    for (const [reason, group] of groupByReason(needsLook)) {
      const { label, remedy } = UNKNOWN_REASONS[reason];
      lines.push(`  ${label} (${group.length}) — ${remedy}`);
      for (const g of groupByValue(group)) lines.push(...formatGroup(g, options, "    "));
    }
    lines.push("");
  }

  if (unchecked.length > 0) {
    lines.push(
      `UNVERIFIED (${unchecked.length}) — matched a known format or entropy heuristic; ` +
        `no liveness check was run.`
    );
    for (const g of groupByValue(unchecked)) lines.push(...formatGroup(g, options));
    lines.push("");
  }

  if (dead.length > 0) {
    // Quiet on purpose. It is not an emergency, but it is still a credential
    // sitting in your source, and "dead" is a claim about today.
    lines.push(
      `CONFIRMED DEAD (${dead.length}) — no longer active, but still in your source. Remove them.`
    );
    for (const g of groupByValue(dead)) {
      const f = g[0];
      const where = g.length === 1 ? locationOf(f) : `${g.length} locations: ${g.map(locationOf).join(", ")}`;
      lines.push(`  [${f.severity}] ${f.description} (${f.ruleId}) — ${where}`);
    }
    lines.push("");
  }

  lines.push(counts);
  return lines.join("\n");
}

/** Unknown findings by reason, in the order the reasons are declared. */
function groupByReason(findings: Finding[]): Array<[UnknownReason, Finding[]]> {
  const groups = new Map<UnknownReason, Finding[]>();
  for (const f of findings) {
    const reason = f.verifyReason ?? "no-verifier";
    const bucket = groups.get(reason);
    if (bucket) bucket.push(f);
    else groups.set(reason, [f]);
  }
  return (Object.keys(UNKNOWN_REASONS) as UnknownReason[])
    .filter((r) => groups.has(r))
    .map((r) => [r, groups.get(r)!]);
}

function locationOf(f: Finding): string {
  return f.commit
    ? `${f.file}:${f.line} (commit ${f.commit.slice(0, 8)})`
    : `${f.file ?? "<text>"}:${f.line}`;
}

/**
 * Occurrences of one credential, collapsed into one entry.
 *
 * Purely a rendering concern, and confined to the text report on purpose. One
 * leaked value copied into forty files is one thing to rotate, and printing it
 * forty times buries the other findings underneath it — on the bugsnag-js
 * benchmark the single worst value accounts for 43 of the occurrences in the
 * post-exclusion set.
 *
 * What this deliberately does NOT do: change how many findings there are. The
 * header and footer still count occurrences, SARIF still emits one result per
 * occurrence, JSON still holds one object per finding, and every occurrence
 * keeps its own fingerprint. Grouping is how the list is drawn, not what is in
 * it — a baseline written before this release matches exactly what it matched
 * before.
 *
 * Grouped by rule as well as value: the same string matching two rules is two
 * different claims about it, and merging them would report one.
 */
function groupByValue(findings: Finding[]): Finding[][] {
  const groups = new Map<string, Finding[]>();
  const order: string[] = [];
  for (const f of findings) {
    const key = `${f.ruleId}\u0000${f.value}`;
    const bucket = groups.get(key);
    if (bucket) bucket.push(f);
    else {
      groups.set(key, [f]);
      order.push(key);
    }
  }
  return order.map((k) => groups.get(k)!);
}

function formatFinding(f: Finding, options: ReportOptions, indent = "  "): string[] {
  return formatGroup([f], options, indent);
}

/**
 * One entry for a group of occurrences. A single-occurrence group renders
 * exactly as it always did, so nothing changes for the common case.
 */
function formatGroup(group: Finding[], options: ReportOptions, indent = "  "): string[] {
  const f = group[0];
  const out = [`${indent}[${f.severity}] ${f.description} (${f.ruleId})`];

  if (group.length === 1) {
    out.push(`${indent}  ${locationOf(f)}`);
  } else {
    out.push(`${indent}  ${group.length} locations, same value:`);
    for (const occurrence of group) out.push(`${indent}    ${locationOf(occurrence)}`);
  }

  out.push(`${indent}  value: ${displayValue(f, options.redact)}`);
  if (f.verifyDetail) out.push(`${indent}  ${f.verifyDetail}`);
  // Every occurrence keeps its own identity, and every one is printed: a
  // baseline entry is per occurrence, so showing only the first would leave
  // someone unable to accept the rest.
  for (const occurrence of group) {
    if (occurrence.fingerprint) out.push(`${indent}  fingerprint: ${occurrence.fingerprint}`);
  }
  return out;
}

function renderJson(findings: Finding[], options: ReportOptions): string {
  return JSON.stringify(
    {
      tool: "secretloop",
      summary: {
        total: findings.length,
        // Scope in the machine-readable formats, not only in the text one. CI
        // consumes exactly json and sarif, so the honest-scope invariant was
        // weakest precisely where the reader is a machine that cannot infer
        // from prose that nothing was looked at.
        scope: options.scope ?? null,
        scannedCount: options.scannedCount ?? null,
        scopeNoun: options.scopeNoun ?? null,
        confirmedLive: findings.filter((f) => f.verifyStatus === "live").length,
        bySeverity: countBy(findings, (f) => f.severity),
        byLiveness: {
          live: findings.filter((f) => f.verifyStatus === "live").length,
          dead: findings.filter((f) => f.verifyStatus === "dead").length,
          unknown: findings.filter((f) => f.verifyStatus === "unknown").length,
          unchecked: findings.filter((f) => f.verifyStatus === undefined).length,
        },
      },
      findings: findings.map((f) => ({
        ruleId: f.ruleId,
        description: f.description,
        severity: f.severity,
        confidence: f.confidence,
        // The `verified` boolean this replaced could not express "unknown",
        // which is how a 403 came to be reported as a revocation. null here
        // means no verification pass ran, distinct from a run that could not
        // reach a verdict.
        verifyStatus: f.verifyStatus ?? null,
        verifyReason: f.verifyReason ?? null,
        verifyDetail: f.verifyDetail ?? null,
        file: f.file ?? null,
        line: f.line,
        commit: f.commit ?? null,
        fingerprint: f.fingerprint ?? null,
        // Rules that matched the same span and yielded to this one.
        alsoMatched: f.alsoMatched ?? null,
        value: displayValue(f, options.redact),
      })),
    },
    null,
    2
  );
}

/**
 * SARIF 2.1.0 — the format GitHub code scanning, GitLab, and most CI dashboards
 * ingest. Without it, findings can't be surfaced natively in a PR, which is the
 * one place developers reliably look.
 */
function renderSarif(findings: Finding[], options: ReportOptions): string {
  const ruleIds = [...new Set(findings.map((f) => f.ruleId))];
  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "SecretLoop",
            rules: ruleIds.map((id) => {
              const sample = findings.find((f) => f.ruleId === id)!;
              return {
                id,
                name: id,
                shortDescription: { text: sample.description },
                defaultConfiguration: { level: sarifLevel(sample) },
                properties: { tags: ["security", "secret"], "security-severity": securityScore(sample) },
              };
            }),
          },
        },
        // SARIF's own place for "what this run did". executionSuccessful is the
        // object's only required property; everything SecretLoop-specific goes
        // in the properties bag the format provides for exactly that, so the
        // document stays valid rather than gaining invented siblings.
        invocations: [
          {
            executionSuccessful: true,
            properties: { scope: options.scope ?? null },
          },
        ],
        results: findings.map((f) => ({
          ruleId: f.ruleId,
          level: sarifLevel(f),
          message: { text: sarifMessage(f, options) },
          // Liveness lives here, not in partialFingerprints: that field is
          // alert identity, and anything unstable in it re-opens every alert.
          properties: {
            alsoMatched: f.alsoMatched ?? null,
            verificationStatus: f.verifyStatus ?? "unchecked",
            verificationReason: f.verifyReason ?? null,
            verificationDetail: f.verifyDetail ?? null,
          },
          // GitHub code scanning keys alert identity off this field, so the name
          // is a one-way door: once alerts exist under it, changing it
          // resurfaces every previously triaged one. Nothing has been published,
          // so this is the last moment it is free to fix — and it was
          // `secretguardFingerprint`, a permanent public reference to a product
          // that never shipped.
          //
          // The `/v2` suffix is SARIF's convention for exactly this problem
          // (GitHub's own is `primaryLocationLineHash/v1`). partialFingerprints
          // is a map, so a future change to how these are derived can publish
          // `/v3` alongside `/v2` and code scanning will match on either,
          // instead of reopening this same door. The number tracks the
          // fingerprint algorithm, which is why it starts at 2: the baseline
          // format it comes from is already v2.
          partialFingerprints: f.fingerprint
            ? { "secretloopFingerprint/v2": f.fingerprint }
            : undefined,
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.file ?? "unknown" },
                region: { startLine: Math.max(1, f.line) },
              },
            },
          ],
        })),
      },
    ],
  };
  return JSON.stringify(sarif, null, 2);
}

/**
 * What a reviewer in code scanning should do about this line.
 *
 * The one non-obvious case is a refused check. A credential the provider does
 * not recognise comes back 401; a 403 means it evaluated the credential and
 * declined, which leans live — and it is precisely the case no amount of
 * retrying resolves, so it stays at error however mild the rule's severity.
 *
 * Every other unknown taught us nothing, so the finding is worth exactly what
 * its format was worth before the check ran.
 */
function sarifLevel(f: Finding): "error" | "warning" | "note" {
  if (f.verifyStatus === "live") return "error";
  if (f.verifyStatus === "dead") return "note";
  if (f.verifyReason === "provider-refused") return "error";
  if (f.confidence === "entropy-heuristic") return "note";
  return f.severity === "critical" || f.severity === "high" ? "error" : "warning";
}

function sarifMessage(f: Finding, options: ReportOptions): string {
  const value = `Value: ${displayValue(f, options.redact)}`;
  switch (f.verifyStatus) {
    case "live":
      return `${f.description} — CONFIRMED LIVE. ${value}`;
    case "dead":
      return `${f.description} — confirmed no longer active, but still present in source. ${value}`;
    case "unknown":
      return (
        `${f.description} — liveness unknown: ` +
        `${UNKNOWN_REASONS[f.verifyReason ?? "no-verifier"].label}. ${value}`
      );
    default:
      return `${f.description}. ${value}`;
  }
}

function securityScore(f: Finding): string {
  if (f.verifyStatus === "live") return "9.8";
  if (f.verifyStatus === "dead") return "1.0";
  switch (f.severity) {
    case "critical":
      return "8.0";
    case "high":
      return "6.5";
    case "medium":
      return "4.0";
    default:
      return "2.0";
  }
}

function countBy<T>(items: T[], key: (item: T) => string): Record<string, number> {
  const out: Record<string, number> = {};
  for (const item of items) {
    const k = key(item);
    out[k] = (out[k] ?? 0) + 1;
  }
  return out;
}
