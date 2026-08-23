#!/usr/bin/env node
import { writeFileSync } from "fs";
import * as path from "path";
import { Finding, scanText } from "./scanner";
import { loadConfig, loadBaseline, legacyConfigNotice, SecretLoopConfig } from "./config";
import { listFiles, readTextFile, getStagedFiles, findRepoRoot } from "./walk";
import { scanHistory, isGitRepo } from "./history";
import { render, OutputFormat, sortFindings } from "./report";
import { isVerifiable, verifyFinding } from "./verify";

/**
 * One binary that covers the three places secrets get caught: the working tree
 * (CI), the staged diff (pre-commit), and git history (the backlog nobody has
 * looked at). `--verify` optionally proves liveness, which is the difference
 * between a list of maybes and a prioritized list of things to rotate today.
 */

interface Args {
  command: "scan" | "staged" | "history" | "help";
  format: OutputFormat;
  verify: boolean;
  redact: boolean;
  baseline?: string;
  writeBaseline?: string;
  output?: string;
  maxCommits?: number;
  revRange?: string;
  root: string;
  /** Only fail the process on findings at or above this severity. */
  failOn: "any" | "verified" | "critical" | "high" | "never";
}

function parseArgs(argv: string[]): Args {
  const args: Args = {
    command: "scan",
    format: "text",
    verify: false,
    redact: true,
    root: process.cwd(),
    failOn: "any",
  };

  const positional = argv.filter((a) => !a.startsWith("-"));
  if (positional.length > 0 && ["scan", "staged", "history", "help"].includes(positional[0])) {
    args.command = positional[0] as Args["command"];
  }
  if (argv.includes("--help") || argv.includes("-h")) args.command = "help";

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => argv[++i];
    switch (a) {
      case "--format":
        args.format = next() as OutputFormat;
        break;
      case "--verify":
        args.verify = true;
        break;
      case "--no-redact":
        args.redact = false;
        break;
      case "--baseline":
        args.baseline = next();
        break;
      case "--write-baseline":
        args.writeBaseline = next();
        break;
      case "--output":
      case "-o":
        args.output = next();
        break;
      case "--max-commits":
        args.maxCommits = Number(next());
        break;
      case "--rev-range":
        args.revRange = next();
        break;
      case "--path":
        args.root = path.resolve(next());
        break;
      case "--fail-on":
        args.failOn = next() as Args["failOn"];
        break;
    }
  }
  return args;
}

const HELP = `secretloop - detect exposed secrets, verify whether they are live,
and rotate or remediate them. A GPY Analytics product.

USAGE
  secretloop <command> [options]

COMMANDS
  scan       Scan the working tree (default)
  staged     Scan staged changes only (used by the pre-commit hook)
  history    Scan git history for secrets committed at any point
  help       Show this message

OPTIONS
  --verify                 Confirm liveness against the provider's API before reporting
  --format <text|json|sarif>   Output format (default: text)
  -o, --output <file>      Write the report to a file instead of stdout
  --no-redact              Print full secret values (dangerous in CI logs)
  --baseline <file>        Ignore findings listed in this baseline file
  --write-baseline <file>  Write current findings to a baseline and exit 0
  --max-commits <n>        history: only scan the most recent n commits
  --rev-range <range>      history: scan a rev range, e.g. origin/main..HEAD
  --path <dir>             Directory to scan (default: cwd)
  --fail-on <any|verified|critical|high|never>
                           Which findings cause a non-zero exit (default: any)

EXAMPLES
  secretloop scan --verify --format sarif -o results.sarif
  secretloop history --max-commits 500 --verify
  secretloop scan --baseline .secretloop-baseline.json --fail-on verified

The secretguard command still works as a deprecated alias for secretloop.
`;

async function verifyAll(findings: Finding[], texts: Map<string, string>): Promise<void> {
  const verifiable = findings.filter((f) => isVerifiable(f.ruleId));
  // Bounded concurrency: enough to be fast, low enough not to look like an
  // attack to a provider's rate limiter.
  const CONCURRENCY = 5;
  let cursor = 0;
  const workers = Array.from({ length: Math.min(CONCURRENCY, verifiable.length) }, async () => {
    while (cursor < verifiable.length) {
      const f = verifiable[cursor++];
      const result = await verifyFinding(f, {
        fullText: texts.get(f.file ?? "") ?? "",
        fetchImpl: fetch,
      });
      if (!result) continue;
      f.verified = result.verified;
      f.verifyDetail = result.detail;
      if (result.verified) f.confidence = "verified-live";
    }
  });
  await Promise.all(workers);
}

function applyBaseline(findings: Finding[], baselineFile?: string): Finding[] {
  if (!baselineFile) return findings;
  const accepted = loadBaseline(baselineFile);
  return findings.filter((f) => !f.fingerprint || !accepted.has(f.fingerprint));
}

function shouldFail(findings: Finding[], failOn: Args["failOn"]): boolean {
  if (failOn === "never" || findings.length === 0) return false;
  switch (failOn) {
    case "verified":
      return findings.some((f) => f.verified === true);
    case "critical":
      return findings.some((f) => f.severity === "critical");
    case "high":
      return findings.some((f) => f.severity === "critical" || f.severity === "high");
    default:
      return true;
  }
}

function scanFileList(
  root: string,
  files: string[],
  config: SecretLoopConfig
): { findings: Finding[]; texts: Map<string, string> } {
  const findings: Finding[] = [];
  const texts = new Map<string, string>();
  for (const rel of files) {
    const text = readTextFile(root, rel, config);
    if (text === null) continue;
    texts.set(rel, text);
    findings.push(...scanText(text, { config, filePath: rel }));
  }
  return { findings, texts };
}

/**
 * The binary is installed under both `secretloop` and the pre-rebrand
 * `secretguard`. Both run this same entry point with identical behavior; the
 * old name only adds a notice, so existing hooks, CI jobs, and scripts keep
 * working untouched. The notice goes to stderr so it can never corrupt piped
 * JSON or SARIF on stdout.
 */
function warnIfLegacyInvocation(): void {
  const invokedAs = path.basename(process.argv[1] ?? "");
  if (/^secretguard(\.js|\.cmd)?$/i.test(invokedAs)) {
    process.stderr.write(
      "secretloop: `secretguard` is a deprecated alias and will keep working for now. " +
        "Use `secretloop` instead.\n"
    );
  }
}

async function main(): Promise<void> {
  warnIfLegacyInvocation();

  const args = parseArgs(process.argv.slice(2));
  if (args.command === "help") {
    process.stdout.write(HELP);
    process.exit(0);
  }

  const root = findRepoRoot(args.root);
  const configNotice = legacyConfigNotice(root);
  if (configNotice) process.stderr.write(`secretloop: ${configNotice}\n`);
  const config = loadConfig(root);

  let findings: Finding[];
  let texts = new Map<string, string>();

  if (args.command === "history") {
    if (!isGitRepo(root)) {
      process.stderr.write("secretloop: history scan requires a git repository.\n");
      process.exit(2);
    }
    findings = scanHistory({
      config,
      repoRoot: root,
      maxCommits: args.maxCommits,
      revRange: args.revRange,
    });
  } else {
    const files = args.command === "staged" ? getStagedFiles(root) : listFiles(root, config);
    const result = scanFileList(root, files, config);
    findings = result.findings;
    texts = result.texts;
  }

  if (args.verify) await verifyAll(findings, texts);

  findings = applyBaseline(findings, args.baseline);

  if (args.writeBaseline) {
    const fingerprints = [...new Set(findings.map((f) => f.fingerprint).filter(Boolean))];
    writeFileSync(
      args.writeBaseline,
      JSON.stringify({ version: 1, fingerprints }, null, 2) + "\n",
      "utf8"
    );
    process.stdout.write(
      `secretloop: wrote ${fingerprints.length} fingerprint(s) to ${args.writeBaseline}.\n` +
        `Future scans will ignore these; new findings still fail.\n`
    );
    process.exit(0);
  }

  const report = render(sortFindings(findings), args.format, { redact: args.redact, root });
  if (args.output) writeFileSync(args.output, report + "\n", "utf8");
  else process.stdout.write(report + "\n");

  if (args.command === "staged" && findings.length > 0 && args.format === "text") {
    process.stdout.write(
      "\nFix these, annotate a false positive with `secretloop:allow`, or bypass with " +
        "`git commit --no-verify`.\n"
    );
  }

  process.exit(shouldFail(findings, args.failOn) ? 1 : 0);
}

main().catch((err) => {
  process.stderr.write(`secretloop: ${err?.message ?? err}\n`);
  process.exit(2);
});
