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
import { listFilesWithExclusions, filterGenerated, getStagedFiles, findRepoRoot } from "./walk";
import { scanFiles } from "./workspace";
import { scanHistory, isGitRepo, InvalidRevRangeError } from "./history";
import { render, OutputFormat, sortFindings, UNKNOWN_REASONS, describeScope } from "./report";
import { verifyFindings } from "./verify";

/**
 * One binary that covers the three places secrets get caught: the working tree
 * (CI), the staged diff (pre-commit), and git history (the backlog nobody has
 * looked at). `--verify` optionally proves liveness, which is the difference
 * between a list of maybes and a prioritized list of things to rotate today.
 */

export interface Args {
  command: "scan" | "staged" | "history" | "mask" | "help";
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
   * Scan the generated-file group too. Bypasses ONLY that group — the base
   * exclusions (node_modules, package-lock.json, minified bundles) stay on, as
   * they always have.
   */
  includeGenerated: boolean;
  /** Report generic-tier findings in test, fixture and example paths. */
  includeFixtures: boolean;
  /**
   * Require a secret-like word in the identifier before generic-high-entropy
   * reports. True by default; `--no-key-context` clears it. Bypasses ONLY that
   * gate -- the ordered-run and path-shape vetoes, the post-prefix floor and
   * every named rule are untouched.
   */
  keyContext: boolean;
  /** mask: also mask generic high-entropy strings. Off by default -- see HELP. */
  entropy: boolean;
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

/** The commands the CLI answers to. */
const COMMANDS: readonly Args["command"][] = ["scan", "staged", "history", "mask", "help"];

export function parseArgs(argv: string[]): Args {
  const args: Args = {
    command: "scan",
    format: "text",
    verify: false,
    redact: true,
    root: process.cwd(),
    failOn: "any",
    includeGenerated: false,
    includeFixtures: false,
    keyContext: true,
    entropy: false,
  };
  const errors: string[] = [];

  // Tokens the loop did not consume as a flag's value. The command comes from
  // here rather than from a filter over argv, because `argv.filter(a =>
  // !a.startsWith("-"))` cannot tell a command from a value: for
  // `secretloop --format json` it yields "json", and for `--baseline history`
  // it yielded "history", which switched the run to a git-history scan because
  // of what a file happened to be called.
  const loose: string[] = [];
  // Help wins over everything below, including the complaints. Someone reaching
  // for --help is not asking to be told their other arguments are wrong.
  const wantsHelp = argv.includes("--help") || argv.includes("-h");

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    /**
     * The value for `flag`, or undefined when there is not a usable one.
     *
     * Both failure modes used to be silent. `next()` was `argv[++i]` with no
     * bounds check, so a flag at the end of argv got undefined — `--output`
     * wrote no file, `--write-baseline` wrote no baseline, `--path` handed
     * path.resolve undefined and threw from inside a TypeError that named
     * "paths[0]" rather than the flag. And a flag followed by another flag
     * swallowed it: `--format --verify` set the format to "--verify" and left
     * verification off, on a run whose whole point was to verify.
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
      case "--include-generated":
        args.includeGenerated = true;
        break;
      case "--include-fixtures":
        args.includeFixtures = true;
        break;
      case "--no-key-context":
        args.keyContext = false;
        break;
      case "--entropy":
        args.entropy = true;
        break;
      case "--help":
      case "-h":
        // Answered above. Listed so it is not reported as an unknown option.
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
      default:
        // The switch had no default, so anything it did not recognise was
        // dropped: `--fail-onn critical` left the gate at its default and
        // `--outputt results.json` reported to stdout while the file the user
        // named was never created. A check quietly not applied is worse than
        // one nobody asked for.
        if (a.startsWith("-")) errors.push(`unknown option ${a}.`);
        else loose.push(a);
        break;
    }
  }

  // Only the first loose token is judged. A run with an unknown option usually
  // strands that option's value here too, and two messages for one mistake is
  // one more than anyone needs.
  const command = loose[0];
  if (command !== undefined) {
    if ((COMMANDS as readonly string[]).includes(command)) {
      args.command = command as Args["command"];
    } else {
      // `secretloop hisotry` used to scan the working tree and report
      // "Scanned 54 file(s)" while the history it was asked about went
      // unlooked-at.
      errors.push(`unknown command ${command}. Use one of: ${COMMANDS.join(", ")}.`);
    }
  }
  if (wantsHelp) args.command = "help";

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
  mask       Read stdin, write it back with every secret replaced
  help       Show this message

OPTIONS
  --verify                 Confirm liveness against the provider's API before reporting
  --include-generated      Also scan generated files (lockfiles, Gradle/Maven
                           wrappers, Xcode project files, SARIF reports). Does
                           not re-enable node_modules, package-lock.json or
                           minified bundles, which are never scanned.
  --entropy                mask: also mask generic high-entropy strings.
                           OFF by default, which is the opposite of a scan.
                           Masking every digest, UUID and hash in a log
                           destroys the log's usefulness while protecting
                           nothing -- those are not credentials.
  --include-fixtures       Also report generic-tier findings in test, fixture
                           and example paths. Named provider rules already fire
                           there; this is only about the generic tiers.
  --no-key-context         Report generic high-entropy strings whatever they are
                           called. By default that tier fires only when the
                           identifier carries a secret-like word (key, token,
                           secret, password, auth...), because a value's shape
                           alone is a weak guess. Turning this off restores the
                           pre-0.1.4 behaviour of that ONE gate; every other
                           filter and every named rule is unaffected.
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
  kubectl logs pod | secretloop mask | pbcopy   # paste a log safely
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
  // --write-baseline accepts every current finding and returns before the
  // report is rendered. With --verify, the verification pass has already run by
  // then: every detected credential was sent to its provider and every verdict
  // was thrown away. Not a leak and not a lie — the outbound record counted
  // each call honestly — but network traffic carrying a user's live credentials
  // in service of nothing.
  //
  // Rejected rather than reordered or quietly skipped. Skipping the pass would
  // be the friendlier default and the wrong one: --verify is the flag that
  // sends credentials to third parties, and a run that ignores it teaches that
  // it is advisory. Which runnable combinations make sense is a question for
  // the command line, and this is not one of them.
  if (args.verify && args.writeBaseline) {
    return (
      "--verify and --write-baseline cannot be used together. --write-baseline " +
      "accepts every current finding and exits before reporting, so verification " +
      "would send each credential to its provider and discard the answer. Write " +
      "the baseline first, then verify against it."
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
 * Re-exported from report.ts, where it now lives.
 *
 * It moved because the extension has to say the same sentence, and importing it
 * from here would compile the CLI's `main()` into out/extension.js as a
 * top-level statement — esbuild inlines ESM modules flat, so cli.ts's
 * `require.main === module` guard becomes a property of whichever bundle it
 * lands in. Harmless in the extension host, which loads the bundle with
 * require(), and a live scan of the working directory for anyone who ever runs
 * it directly. report.ts is imported by both sides already and has no top-level
 * effects, so it is the safe home.
 *
 * Kept exported here so every existing import site and test is untouched.
 */
export { describeScope } from "./report";

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

interface ScannedList {
  findings: Finding[];
  texts: Map<string, string>;
  suppressed: number;
  fixtureSuppressed: number;
  /** Enumerated but never read: over the size cap, binary, or outside the root. */
  oversized: number;
  unreadable: number;
  outside: number;
}

function scanFileList(root: string, files: string[], config: SecretLoopConfig): ScannedList {
  let oversized = 0;
  let unreadable = 0;
  let outside = 0;
  // Same enumeration and same guards the editor uses, so the two cannot report
  // different files for the same project.
  const scanned = scanFiles(root, files, config, {
    onSkipped: (reason) => {
      if (reason === "oversized") oversized++;
      else if (reason === "outside") outside++;
      else unreadable++;
    },
  });
  return {
    findings: scanned.flatMap((s) => s.findings),
    texts: new Map(scanned.map((s) => [s.path, s.text])),
    suppressed: scanned.reduce((n, s) => n + (s.suppressed ?? 0), 0),
    fixtureSuppressed: scanned.reduce((n, s) => n + (s.fixtureSuppressed ?? 0), 0),
    oversized,
    unreadable,
    outside,
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

  // Before the mask dispatch, not after it.
  //
  // validateArgs reports args.errors first and is the only reader of them, so
  // dispatching mask ahead of it threw every parse error away for the one
  // command whose failure mode is an unmasked secret: `mask --entropoy` masked
  // with the generic tier off and exited 0. Only the argv errors are checked
  // here -- the combination rules below are about scan/history flags and have
  // nothing to say about a transform.
  const argError = args.errors?.[0];
  if (argError) {
    process.stderr.write(`secretloop: ${argError}\n`);
    process.exitCode = 2;
    return;
  }

  if (args.command === "mask") {
    process.exitCode = await runMask(args);
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
  // Emptying the group is the whole mechanism: everything downstream asks
  // classifyPath, which then has nothing in this group to match. The base
  // exclusions are a different array and are untouched, so no flag can widen
  // the scan beyond what it has always been able to reach.
  if (args.includeGenerated) config.generatedExcludePaths = [];
  if (args.includeFixtures) config.includeFixtures = true;
  if (!args.keyContext) config.keyContextRequired = false;

  let findings: Finding[];
  let texts = new Map<string, string>();
  // What the header says was covered. "55 findings" means something different
  // over 31 commits than over 4 staged files.
  let scope: string | undefined;
  // The same facts as numbers, for the machine-readable formats.
  let scannedCount: number | undefined;
  let scopeNoun: string | undefined;

  if (args.command === "history") {
    if (!isGitRepo(root)) {
      process.stderr.write("secretloop: history scan requires a git repository.\n");
      process.exitCode = 2;
      return;
    }
    let commitsScanned = 0;
    let generatedExcluded = 0;
    let suppressed = 0;
    let fixtureSuppressed = 0;
    try {
      findings = await scanHistory({
        config,
        repoRoot: root,
        maxCommits: args.maxCommits,
        revRange: args.revRange,
        onProgress: (commits) => (commitsScanned = commits),
        onGeneratedExcluded: (count) => (generatedExcluded = count),
        onSuppressed: (count) => (suppressed = count),
        onFixtureSuppressed: (count) => (fixtureSuppressed = count),
      });
    } catch (err) {
      // scanHistory refuses a range git would read as an option. Caught here so
      // the message names the flag the person typed rather than the parameter
      // the scanner calls it -- the guard is shared, the vocabulary is not.
      if (err instanceof InvalidRevRangeError) {
        process.stderr.write(`secretloop: --rev-range ${err.revRange} was refused: ${err.message}\n`);
        process.exitCode = 2;
        return;
      }
      throw err;
    }
    scope = describeScope(commitsScanned, "commit", { generatedExcluded, suppressed, fixtureSuppressed });
    scannedCount = commitsScanned;
    scopeNoun = "commit";
  } else {
    let listed;
    if (args.command === "staged") {
      const staged = getStagedFiles(root);
      // "git could not answer" is not "nothing is staged". Reported as an
      // environment error rather than folded into an empty scan, because the
      // pre-commit hook exits on this code path and a 0 here lets the commit
      // through on a scan that never ran.
      if ("error" in staged) {
        process.stderr.write(`secretloop: ${staged.error}\n`);
        process.exitCode = 2;
        return;
      }
      listed = filterGenerated(root, staged.files, config);
    } else {
      listed = listFilesWithExclusions(root, config);
    }
    const result = scanFileList(root, listed.files, config);
    findings = result.findings;
    texts = result.texts;
    scopeNoun = args.command === "staged" ? "staged file" : "file";
    scannedCount = result.texts.size;
    scope = describeScope(result.texts.size, scopeNoun, {
      generatedExcluded: listed.generatedExcluded,
      suppressed: result.suppressed,
      // The read enforces containment too, and it can disagree with the walk
      // if a link is retargeted between the two. Added to the walk's count
      // rather than given a clause of its own: it is the same fact, and the
      // sentence already names it.
      outsideExcluded: listed.outsideExcluded + result.outside,
      fixtureSuppressed: result.fixtureSuppressed,
      oversizedExcluded: result.oversized,
      unreadableExcluded: result.unreadable,
    });
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

  const report = render(sortFindings(findings), args.format, {
    redact: args.redact,
    root,
    scope,
    scannedCount,
    scopeNoun,
  });
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
  if (gate.fail) {
    // stderr, never stdout: the report on stdout is piped into files and
    // dashboards, and a byte added there would change every consumer's input.
    // A non-zero exit from a scanner reads as a crash to anyone who has not met
    // this flag before, and the report itself gives them no way to tell.
    process.stderr.write(
      "secretloop: exit 1: findings at or above the fail-on threshold " +
        "(this is the CI gate, not an error)\n"
    );
  }
  process.exitCode = gate.fail ? 1 : 0;
}

/**
 * `secretloop mask` — stdin in, the same text out with every secret replaced.
 *
 * A transform, not a gate: it exits 0 whether or not it found anything, because
 * a filter in the middle of a pipe that fails the pipeline is not a filter.
 *
 * Masked text is the ONLY thing on stdout. The summary goes to stderr, so
 * `... | secretloop mask | pbcopy` puts the masked text on the clipboard and
 * nothing else. That split is the whole ergonomic point of the command.
 */
async function runMask(args: Args): Promise<number> {
  const { scanText, maskFindings } = await import("./scanner");
  const { defaultConfig } = await import("./config");

  // The WHOLE input, before any scanning. A chunked scan cannot see a PEM block
  // that straddles two reads, and "it usually arrives in one chunk" is not a
  // property worth relying on for a redaction tool.
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
  const buf = Buffer.concat(chunks);

  // The defaults, and deliberately NOT the project config.
  //
  // This used to be loadConfig(findRepoRoot(process.cwd())), so whichever
  // repository you happened to be standing in decided what got masked:
  // `{"allowValues":[".*"]}` or an excludeRules list passed every credential
  // through to stdout under "masked 0 finding(s)". The comment that stood here
  // argued the fallback was safe because "defaults mask more, never less" --
  // true of a MALFORMED config, and false of a valid one, which is the case
  // that mattered.
  //
  // A stream piped through a scrubber is not that repository's findings. Rule
  // selection here is a property of the transform, so it comes from one place
  // that no file on disk can widen.
  const config = { ...defaultConfig };

  if (buf.length > config.maxFileSizeBytes) {
    process.stderr.write(
      `secretloop: input is too large to mask (${buf.length} bytes, limit ${config.maxFileSizeBytes}). ` +
        `Nothing was written — masking a stream this size would mean scanning it in pieces, ` +
        `and a secret split across two pieces would pass through unmasked.\n`
    );
    return 2;
  }
  // The same NUL heuristic readTextFile uses. Refusing is the point: passing
  // binary through unchanged would look like it had been masked.
  if (buf.subarray(0, 8000).includes(0)) {
    process.stderr.write(
      "secretloop: input looks binary (NUL byte near the start). Nothing was written — " +
        "SecretLoop cannot mask what it cannot read as text, and passing it through " +
        "unchanged would look like it had been.\n"
    );
    return 2;
  }

  const text = buf.toString("utf8");
  const findings = scanText(text, {
    config: { ...config, entropyPassEnabled: args.entropy, includeFixtures: true },
    // A directive is a triage decision about a repository. This is a stream
    // someone asked to be scrubbed, and honouring `# gitleaks:allow` on the
    // line beside a credential put that credential on stdout unmasked and
    // uncounted. See ScanOptions.honorInlineDirectives.
    honorInlineDirectives: false,
  });

  const masked = maskFindings(text, findings);

  process.stdout.write(masked);

  if (findings.length > 0) {
    const byRule = new Map<string, number>();
    for (const f of findings) byRule.set(f.ruleId, (byRule.get(f.ruleId) ?? 0) + 1);
    const detail = [...byRule.entries()].sort().map(([r, n]) => `${r} x${n}`).join(", ");
    process.stderr.write(`secretloop: masked ${findings.length} finding(s): ${detail}\n`);
  } else {
    process.stderr.write("secretloop: masked 0 finding(s).\n");
  }
  return 0;
}

// Only run the CLI when invoked as a program. Without this guard, importing
// this module for a unit test would scan the cwd and set the process exit code.
if (require.main === module) {
  main().catch((err) => {
    process.stderr.write(`secretloop: ${err?.message ?? err}\n`);
    process.exitCode = 2;
  });
}
