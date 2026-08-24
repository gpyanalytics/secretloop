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
  if (findings.length === 0) return "SecretLoop: no secrets found.";

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
    for (const f of live) lines.push(...formatFinding(f, options));
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
      for (const f of group) lines.push(...formatFinding(f, options, "    "));
    }
    lines.push("");
  }

  if (unchecked.length > 0) {
    lines.push(
      `UNVERIFIED (${unchecked.length}) — matched a known format or entropy heuristic; ` +
        `no liveness check was run.`
    );
    for (const f of unchecked) lines.push(...formatFinding(f, options));
    lines.push("");
  }

  if (dead.length > 0) {
    // Quiet on purpose. It is not an emergency, but it is still a credential
    // sitting in your source, and "dead" is a claim about today.
    lines.push(
      `CONFIRMED DEAD (${dead.length}) — no longer active, but still in your source. Remove them.`
    );
    for (const f of dead) {
      const loc = f.commit ? `${f.file}:${f.line} (commit ${f.commit.slice(0, 8)})` : `${f.file ?? "<text>"}:${f.line}`;
      lines.push(`  [${f.severity}] ${f.description} (${f.ruleId}) — ${loc}`);
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

function formatFinding(f: Finding, options: ReportOptions, indent = "  "): string[] {
  const loc = f.commit
    ? `${f.file}:${f.line} (commit ${f.commit.slice(0, 8)})`
    : `${f.file ?? "<text>"}:${f.line}`;
  const out = [
    `${indent}[${f.severity}] ${f.description} (${f.ruleId})`,
    `${indent}  ${loc}`,
    `${indent}  value: ${displayValue(f, options.redact)}`,
  ];
  if (f.verifyDetail) out.push(`${indent}  ${f.verifyDetail}`);
  if (f.fingerprint) out.push(`${indent}  fingerprint: ${f.fingerprint}`);
  return out;
}

function renderJson(findings: Finding[], options: ReportOptions): string {
  return JSON.stringify(
    {
      tool: "secretloop",
      summary: {
        total: findings.length,
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
