#!/usr/bin/env node
// First, and deliberately: this refuses an unsupported Node before any other
// module initializes. See src/node-guard.ts — the import order is the mechanism.
import "./node-guard";
import { writeFileSync, statSync } from "fs";
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
  /**
   * Everything wrong with the argv this was parsed from, in the order it was
   * found. validateArgs reports the first, so a malformed invocation exits 2
   * through the same path as every other usage error.
   */
  errors?: string[];
}

/** The formats --format accepts, and the only ones render() can produce. */
const FORMATS: readonly OutputFormat[] = ["text", "json", "sarif"];

/** The modes --fail-on accepts. Anything else lands on evaluateGate's default. */
const FAIL_ON_MODES: readonly Args["failOn"][] = ["any", "verified", "critical", "high", "never"];

export function parseArgs(argv: string[]): Args {
  const args: Args = {
    command: "scan",
    format: "text",
    verify: false,
    redact: true,
    root: process.cwd(),
    failOn: "any",
  };
  const errors: string[] = [];

  const positional = argv.filter((a) => !a.startsWith("-"));
  if (positional.length > 0 && ["scan", "staged", "history", "help"].includes(positional[0])) {
    args.command = positional[0] as Args["command"];
  }
  // Help wins over everything below, including the complaints. Someone reaching
  // for --help is not asking to be told their other arguments are wrong.
  const wantsHelp = argv.includes("--help") || argv.includes("-h");
  if (wantsHelp) args.command = "help";

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    /**
     * The value for `flag`, or undefined when there is not a usable one.
     *
     * Both failure modes used to be silent. `next()` was `argv[++i]` with no
     * bounds check, so a flag at the end of argv got undefined — `--output`
     * wrote no file, `--write-baseline` wrote no baseline, `--path` handed
     * path.resolve undefined and threw a TypeError naming "paths[0]" rather
     * than the flag. And a flag followed by another flag swallowed it:
     * `--format --verify` set the format to "--verify" and left verification
     * off, on a run whose whole point was to verify.
     *
     * A flag-shaped token is reported but NOT consumed, so it still parses as
     * itself on the next iteration and `--verify` above still takes effect.
     */
    const value = (flag: string): string | undefined => {
      const candidate = argv[i + 1];
      if (candidate === undefined) {
        errors.push(`${flag} requires a value.`);
        return undefined;
      }
      if (candidate.startsWith("-")) {
        errors.push(`${flag} requires a value, but was given ${candidate}.`);
        return undefined;
      }
      i++;
      return candidate;
    };
    switch (a) {
      case "--format": {
        const format = value("--format");
        if (format === undefined) break;
        // render() falls through to text for anything it does not recognise, so
        // `--format sariff -o results.sarif` wrote a text file that
        // upload-sarif could not read, and said nothing.
        if (FORMATS.includes(format as OutputFormat)) args.format = format as OutputFormat;
        else errors.push(`--format ${format} is not a known format. Use one of: ${FORMATS.join(", ")}.`);
        break;
      }
      case "--verify":
        args.verify = true;
        break;
      case "--no-redact":
        args.redact = false;
        break;
      case "--baseline":
        args.baseline = value("--baseline") ?? args.baseline;
        break;
      case "--write-baseline":
        args.writeBaseline = value("--write-baseline") ?? args.writeBaseline;
        break;
      case "--output":
      case "-o":
        args.output = value(a) ?? args.output;
        break;
      case "--max-commits": {
        // The one flag whose value is read as a number before it is judged
        // flag-shaped: -5 is a bad limit, not a missing one, and the message
        // has to fit the fault. So it is consumed either way.
        const candidate = argv[i + 1];
        if (candidate === undefined) {
          errors.push("--max-commits requires a value.");
          break;
        }
        i++;
        const limit = Number(candidate);
        // NaN and 0 are both falsy, so scanHistory's `if (options.maxCommits)`
        // dropped them and scanned the whole history; -5 reached git as `-n-5`,
        // which git treats as no limit at all.
        if (!Number.isInteger(limit) || limit < 1) {
          errors.push(`--max-commits ${candidate} is not a positive integer.`);
        } else {
          args.maxCommits = limit;
        }
        break;
      }
      case "--rev-range":
        args.revRange = value("--rev-range") ?? args.revRange;
        break;
      case "--path": {
        const root = value("--path");
        if (root !== undefined) args.root = path.resolve(root);
        break;
      }
      case "--fail-on": {
        const failOn = value("--fail-on");
        if (failOn === undefined) break;
        // evaluateGate's default branch treats anything unrecognised as "any",
        // so `--fail-on hgih` silently became the strictest mode there is.
        if ((FAIL_ON_MODES as readonly string[]).includes(failOn)) {
          args.failOn = failOn as Args["failOn"];
        } else {
          errors.push(
            `--fail-on ${failOn} is not a known mode. Use one of: ${FAIL_ON_MODES.join(", ")}.`
          );
        }
        break;
      }
    }
  }

  if (errors.length > 0 && !wantsHelp) args.errors = errors;
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
  // Reported ahead of the combination rules below: a malformed argument makes
  // the command unrunnable at all, while those rules are about which runnable
  // combinations make sense. The first one is enough to send someone back to
  // their command line.
  if (args.errors && args.errors.length > 0) return args.errors[0];

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

/**
 * Whether the directory a scan was pointed at can be scanned at all.
 *
 * Every layer below this one fails soft, and the failures compose into a lie:
 * `git rev-parse` in a directory that isn't there errors, so findRepoRoot hands
 * back the bad path unchanged; `git ls-files` fails, so listFiles falls through
 * to a walk; readdirSync throws, so the walk returns nothing. Three reasonable
 * fallbacks, and `--path ./scr` exits 0 saying no secrets were found.
 *
 * Fail soft on a file you cannot read. Fail loudly on a root you were handed,
 * because a mistyped path is the caller's mistake and only the caller can fix
 * it.
 */
export function validateRoot(root: string): string | null {
  let stat;
  try {
    stat = statSync(root);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return `${root} does not exist.`;
    if (code === "EACCES") return `${root} is not readable.`;
    return `${root} could not be read: ${(err as Error).message}`;
  }
  if (!stat.isDirectory()) return `${root} is not a directory.`;
  return null;
}

/**
 * What the report says was covered.
 *
 * Zero is called out rather than left to read as a pass. An excludePaths entry
 * that swallowed the tree, an empty rev-range and a repository with no commits
 * all arrive here, and "Scanned 0 file(s)." is a true sentence that a reader
 * skims as a clean bill of health.
 */
export function describeScope(count: number, noun: string): string {
  if (count === 0) return `0 ${noun}(s) — nothing was scanned, so this is not a clean result`;
  return `${count} ${noun}(s)`;
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

  // Before findRepoRoot, which cannot tell a missing directory from one that
  // simply is not a git repository — it returns the path it was given for both.
  const rootError = validateRoot(args.root);
  if (rootError) {
    process.stderr.write(`secretloop: ${rootError}\n`);
    process.exitCode = 2;
    return;
  }

  const root = findRepoRoot(args.root);
  const config = loadConfig(root);

  let findings: Finding[];
  let texts = new Map<string, string>();
  // What the header says was covered. "55 findings" means something different
  // over 31 commits than over 4 staged files.
  let scope: string | undefined;

  if (args.command === "history") {
    if (!isGitRepo(root)) {
      process.stderr.write("secretloop: history scan requires a git repository.\n");
      process.exitCode = 2;
      return;
    }
    let commitsScanned = 0;
    findings = await scanHistory({
      config,
      repoRoot: root,
      maxCommits: args.maxCommits,
      revRange: args.revRange,
      onProgress: (commits) => (commitsScanned = commits),
    });
    scope = describeScope(commitsScanned, "commit");
  } else {
    const files = args.command === "staged" ? getStagedFiles(root) : listFiles(root, config);
    const result = scanFileList(root, files, config);
    findings = result.findings;
    texts = result.texts;
    scope = describeScope(result.texts.size, args.command === "staged" ? "staged file" : "file");
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

  const report = render(sortFindings(findings), args.format, { redact: args.redact, root, scope });
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
