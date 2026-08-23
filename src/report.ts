import { Finding, redactValue } from "./scanner";

export type OutputFormat = "text" | "json" | "sarif";

export interface ReportOptions {
  /** Mask secret values in the output. Default true — reports end up in CI logs. */
  redact: boolean;
  /** Repo-relative root used for display paths. */
  root: string;
}

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 } as const;

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    // Verified-live first: those are the ones that need action right now.
    const av = a.verified === true ? 0 : 1;
    const bv = b.verified === true ? 0 : 1;
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

  const lines: string[] = [];
  const live = findings.filter((f) => f.verified === true);
  const unknown = findings.filter((f) => f.verified !== true);

  if (live.length > 0) {
    lines.push(`CONFIRMED LIVE (${live.length}) — these credentials currently work. Rotate them.`);
    for (const f of live) lines.push(...formatFinding(f, options));
    lines.push("");
  }
  if (unknown.length > 0) {
    lines.push(`UNVERIFIED (${unknown.length}) — matched a known format or entropy heuristic.`);
    for (const f of unknown) lines.push(...formatFinding(f, options));
    lines.push("");
  }

  lines.push(
    `${findings.length} finding(s): ${live.length} confirmed live, ${unknown.length} unverified.`
  );
  return lines.join("\n");
}

function formatFinding(f: Finding, options: ReportOptions): string[] {
  const loc = f.commit
    ? `${f.file}:${f.line} (commit ${f.commit.slice(0, 8)})`
    : `${f.file ?? "<text>"}:${f.line}`;
  const out = [
    `  [${f.severity}] ${f.description} (${f.ruleId})`,
    `    ${loc}`,
    `    value: ${displayValue(f, options.redact)}`,
  ];
  if (f.verifyDetail) out.push(`    ${f.verifyDetail}`);
  if (f.fingerprint) out.push(`    fingerprint: ${f.fingerprint}`);
  return out;
}

function renderJson(findings: Finding[], options: ReportOptions): string {
  return JSON.stringify(
    {
      tool: "secretloop",
      summary: {
        total: findings.length,
        confirmedLive: findings.filter((f) => f.verified === true).length,
        bySeverity: countBy(findings, (f) => f.severity),
      },
      findings: findings.map((f) => ({
        ruleId: f.ruleId,
        description: f.description,
        severity: f.severity,
        confidence: f.confidence,
        verified: f.verified ?? null,
        verifyDetail: f.verifyDetail ?? null,
        file: f.file ?? null,
        line: f.line,
        commit: f.commit ?? null,
        fingerprint: f.fingerprint ?? null,
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
          message: {
            text: `${f.description}${f.verified === true ? " — CONFIRMED LIVE" : ""}. Value: ${displayValue(f, options.redact)}`,
          },
          // Deliberately still `secretguardFingerprint` after the SecretLoop
          // rebrand. GitHub code scanning keys alert identity off this field:
          // renaming it would make every previously-triaged alert reappear as
          // new on the next upload. The value is unchanged, so dedup keeps
          // working across the rename.
          partialFingerprints: f.fingerprint ? { secretguardFingerprint: f.fingerprint } : undefined,
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

function sarifLevel(f: Finding): "error" | "warning" | "note" {
  if (f.verified === true) return "error";
  if (f.confidence === "entropy-heuristic") return "note";
  return f.severity === "critical" || f.severity === "high" ? "error" : "warning";
}

function securityScore(f: Finding): string {
  if (f.verified === true) return "9.8";
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
