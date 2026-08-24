#!/usr/bin/env node
import { writeFileSync } from "fs";
import * as path from "path";
import { Finding, UnknownReason, scanText } from "./scanner";
import {
  loadConfig,
  loadBaseline,
  BASELINE_VERSION,
  SecretLoopConfig,
} from "./config";
import { listFiles, getStagedFiles, findRepoRoot } from "./walk";
import { scanFiles } from "./workspace";
import { scanHistory, isGitRepo } from "./history";
import { render, OutputFormat, sortFindings, UNKNOWN_REASONS } from "./report";
import { verifyFindings } from "./verify";

/**
 * One binary that covers the three places secrets get caught: the working tree
 * (CI), the staged diff (pre-commit), and git history (the backlog nobody has
 * looked at). `--verify` optionally proves liveness, which is the difference
 * between a list of maybes and a prioritized list of things to rotate today.
 */

export interface Args {
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

export function parseArgs(argv: string[]): Args {
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

export const HELP = `secretloop - detect exposed secrets, verify whether they are live,
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
                           Which findings cause a non-zero exit (default: any).
                           The 'verified' mode requires --verify.

EXAMPLES
  secretloop scan --verify --format sarif -o results.sarif
  secretloop history --max-commits 500 --verify
  secretloop scan --baseline .secretloop-baseline.json --verify --fail-on verified

`;

export function applyBaseline(findings: Finding[], baselineFile?: string): Finding[] {
  if (!baselineFile) return findings;
  const accepted = loadBaseline(baselineFile).fingerprints;
  return findings.filter((f) => !f.fingerprint || !accepted.has(f.fingerprint));
}

/**
 * Fingerprints to record when writing a baseline: everything already accepted,
 * plus everything found this run.
 *
 * The union matters because `findings` has already had the baseline applied, so
 * it holds only what is *new*. Writing just those dropped every previously
 * accepted fingerprint, and the next scan then failed on all of them.
 */
export function mergeBaseline(findings: Finding[], existing: Set<string>): string[] {
  const merged = new Set(existing);
  for (const f of findings) {
    if (f.fingerprint) merged.add(f.fingerprint);
  }
  return [...merged];
}

/**
 * Splits a scan's findings into what gets reported and what gets sent to a
 * provider for liveness verification.
 *
 * Baseline first, verify second. The other order re-sent every already-triaged
 * credential to its provider on every run — findings the team had explicitly
 * accepted and which are then dropped from the report anyway.
 *
 * Both lists hold the same objects: verifyFindings marks findings in place, so
 * copying here would strand the results.
 */
export function triageFindings(
  findings: Finding[],
  args: Args
): { reported: Finding[]; toVerify: Finding[] } {
  const reported = applyBaseline(findings, args.baseline);
  return { reported, toVerify: args.verify ? reported : [] };
}

/**
 * Argument combinations that are cheaper to reject up front than to debug from
 * a green build. Returns null when the arguments are coherent.
 */
export function validateArgs(args: Args): string | null {
  // `--fail-on verified` gates on findings the verification pass marked live.
  // Without `--verify` nothing ever sets that flag, so the gate exits 0 no
  // matter how many live credentials are in the repo.
  //
  // Rejected rather than silently implying `--verify`: that flag sends every
  // detected credential to a provider API, which is not something a flag about
  // exit codes should turn on. It would not close the hole either — with no
  // network egress the implied pass verifies nothing and the build goes green
  // again, just less visibly.
  if (args.failOn === "verified" && !args.verify) {
    return (
      "--fail-on verified requires --verify. Without it no finding is ever " +
      "marked live, so the scan always exits 0."
    );
  }
  // Reading and rewriting one baseline in a single run is ambiguous: it reads
  // as "refresh", but --write-baseline accepts every current finding and exits
  // before reporting. Naming two files makes the intent explicit.
  if (
    args.baseline &&
    args.writeBaseline &&
    path.resolve(args.baseline) === path.resolve(args.writeBaseline)
  ) {
    return (
      "--baseline and --write-baseline cannot name the same file. " +
      "Write to a new file and replace the old one once you have reviewed it."
    );
  }
  return null;
}

export interface GateOutcome {
  fail: boolean;
  /** Why the build failed, when the reason is not simply a live credential. */
  note?: string;
}

/**
 * Decides whether a scan fails the build.
 *
 * `verified` fails on a confirmed-live credential *and* on one that could not be
 * resolved. Passing on unresolved checks is how a runner with no egress went
 * green with live secrets in the repository: every check returned unknown and
 * the gate had nothing to fire on.
 *
 * Unresolved means a check ran and reached no verdict. A rule with no verifier
 * never gets a status at all and is deliberately excluded — otherwise, with 85
 * of 103 rules unverifiable, `verified` would behave like `any` and teams would
 * turn it off, which protects nothing.
 */
export function evaluateGate(findings: Finding[], failOn: Args["failOn"]): GateOutcome {
  if (failOn === "never" || findings.length === 0) return { fail: false };
  switch (failOn) {
    case "verified": {
      const live = findings.filter((f) => f.verifyStatus === "live");
      const unresolved = findings.filter((f) => f.verifyStatus === "unknown");
      if (live.length === 0 && unresolved.length === 0) return { fail: false };
      // A live credential explains itself in the report; an unresolved one does
      // not, and the remedy differs per reason.
      if (unresolved.length === 0) return { fail: true };
      return { fail: true, note: unresolvedNote(unresolved) };
    }
    case "critical":
      return { fail: findings.some((f) => f.severity === "critical") };
    case "high":
      return {
        fail: findings.some((f) => f.severity === "critical" || f.severity === "high"),
      };
    default:
      return { fail: true };
  }
}

function unresolvedNote(unresolved: Finding[]): string {
  const counts = new Map<UnknownReason, number>();
  for (const f of unresolved) {
    const reason = f.verifyReason ?? "no-verifier";
    counts.set(reason, (counts.get(reason) ?? 0) + 1);
  }
  const lines = [
    `--fail-on verified could not vouch for ${unresolved.length} credential(s):`,
  ];
  for (const reason of Object.keys(UNKNOWN_REASONS) as UnknownReason[]) {
    const count = counts.get(reason);
    if (!count) continue;
    const { label, remedy } = UNKNOWN_REASONS[reason];
    lines.push(`  ${count} — ${label}: ${remedy}`);
  }
  return lines.join("\n");
}

function scanFileList(
  root: string,
  files: string[],
  config: SecretLoopConfig
): { findings: Finding[]; texts: Map<string, string> } {
  // Same enumeration and same guards the editor uses, so the two cannot report
  // different files for the same project.
  const scanned = scanFiles(root, files, config);
  return {
    findings: scanned.flatMap((s) => s.findings),
    texts: new Map(scanned.map((s) => [s.path, s.text])),
  };
}


/**
 * Sets process.exitCode and returns rather than calling process.exit().
 *
 * On a pipe, Node's stdout is asynchronous: process.exit() ends the process
 * with bytes still queued, so `secretloop scan --format sarif | tee` could lose
 * the tail of the report. Letting the event loop drain naturally is the only
 * way the whole report reliably arrives.
 */
async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  if (args.command === "help") {
    process.stdout.write(HELP);
    return;
  }

  const usageError = validateArgs(args);
  if (usageError) {
    process.stderr.write(`secretloop: ${usageError}\n`);
    process.exitCode = 2;
    return;
  }

  const root = findRepoRoot(args.root);
  const config = loadConfig(root);

  let findings: Finding[];
  let texts = new Map<string, string>();

  if (args.command === "history") {
    if (!isGitRepo(root)) {
      process.stderr.write("secretloop: history scan requires a git repository.\n");
      process.exitCode = 2;
      return;
    }
    findings = await scanHistory({
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

  if (args.baseline) {
    const loaded = loadBaseline(args.baseline);
    // An outdated baseline matches nothing. Saying so is the difference between
    // "the tool broke" and "regenerate this file".
    if (loaded.outdated) process.stderr.write(`secretloop: ${loaded.notice}\n`);
  }

  const triaged = triageFindings(findings, args);
  findings = triaged.reported;
  if (triaged.toVerify.length > 0) {
    // Context is resolved per finding: each one needs the text of the file it
    // came from, so the AWS verifier pairs an access key ID with the secret key
    // beside it rather than one in some other file.
    await verifyFindings(triaged.toVerify, (f) => ({
      fullText: texts.get(f.file ?? "") ?? "",
      fetchImpl: fetch,
    }));
  }

  if (args.writeBaseline) {
    const existing = args.baseline ? loadBaseline(args.baseline).fingerprints : new Set<string>();
    const fingerprints = mergeBaseline(findings, existing);
    writeFileSync(
      args.writeBaseline,
      JSON.stringify({ version: BASELINE_VERSION, fingerprints }, null, 2) + "\n",
      "utf8"
    );
    process.stdout.write(
      `secretloop: wrote ${fingerprints.length} fingerprint(s) to ${args.writeBaseline}.\n` +
        `Future scans will ignore these; new findings still fail.\n`
    );
    return;
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

  const gate = evaluateGate(findings, args.failOn);
  if (gate.note) process.stderr.write(`secretloop: ${gate.note}\n`);
  process.exitCode = gate.fail ? 1 : 0;
}

// Only run the CLI when invoked as a program. Without this guard, importing
// this module for a unit test would scan the cwd and set the process exit code.
if (require.main === module) {
  main().catch((err) => {
    process.stderr.write(`secretloop: ${err?.message ?? err}\n`);
    process.exitCode = 2;
  });
}
