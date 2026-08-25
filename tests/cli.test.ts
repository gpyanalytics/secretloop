import {
  applyBaseline,
  mergeBaseline,
  parseArgs,
  evaluateGate,
  triageFindings,
  validateArgs,
  validateRoot,
  describeScope,
  HELP,
} from "../src/cli";
import { checkNodeVersion, MIN_NODE } from "../src/node-guard";
import { Finding } from "../src/scanner";
import { test, suite, finish, assert } from "./harness";
import { mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import * as path from "path";

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: "github-token",
    description: "GitHub Personal Access Token",
    value: "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
    startIndex: 0,
    endIndex: 40,
    confidence: "format-match",
    severity: "critical",
    line: 1,
    ...overrides,
  };
}

suite("cli.ts — --fail-on gating");

test("--fail-on verified is rejected without --verify", () => {
  // Nothing sets `verified` unless the verification pass ran, so this
  // combination exits 0 on a repo full of live credentials — the one outcome a
  // CI gate exists to prevent.
  const error = validateArgs(parseArgs(["scan", "--fail-on", "verified"]));
  assert.ok(error, "expected --fail-on verified to be rejected without --verify");
  assert.match(error!, /--verify/);
});

test("--fail-on verified is accepted with --verify", () => {
  assert.strictEqual(validateArgs(parseArgs(["scan", "--fail-on", "verified", "--verify"])), null);
});

test("other --fail-on modes do not require --verify", () => {
  assert.strictEqual(validateArgs(parseArgs(["scan", "--fail-on", "high"])), null);
  assert.strictEqual(validateArgs(parseArgs(["scan", "--fail-on", "any"])), null);
  assert.strictEqual(validateArgs(parseArgs(["scan"])), null);
});

test("the help text never advertises --fail-on verified without --verify", () => {
  // The shipped example was `scan --baseline <f> --fail-on verified`, which is
  // exactly the silent-pass combination this guard now rejects.
  for (const line of HELP.split("\n")) {
    if (!line.includes("--fail-on verified")) continue;
    assert.ok(line.includes("--verify"), `help example must pass --verify: ${line.trim()}`);
  }
});

suite("\ncli.ts — the --fail-on gate");

test("the gate fires on a confirmed-live credential", () => {
  assert.strictEqual(evaluateGate([finding({ verifyStatus: "live" })], "verified").fail, true);
});

test("the gate stays quiet when everything checkable came back dead", () => {
  const outcome = evaluateGate([finding({ verifyStatus: "dead" })], "verified");
  assert.strictEqual(outcome.fail, false);
  assert.strictEqual(outcome.note, undefined);
});

test("--fail-on any fires on any finding at all", () => {
  assert.strictEqual(evaluateGate([finding({ severity: "low" })], "any").fail, true);
  assert.strictEqual(evaluateGate([], "any").fail, false);
});

test("--fail-on high covers critical as well as high", () => {
  assert.strictEqual(evaluateGate([finding({ severity: "critical" })], "high").fail, true);
  assert.strictEqual(evaluateGate([finding({ severity: "high" })], "high").fail, true);
  assert.strictEqual(evaluateGate([finding({ severity: "medium" })], "high").fail, false);
});

test("--fail-on never never fires", () => {
  assert.strictEqual(evaluateGate([finding({ verifyStatus: "live" })], "never").fail, false);
});

suite("\ncli.ts — unresolved checks fail the verified gate");

test("a credential that could not be checked fails the gate", () => {
  // The runner with no egress used to pass green with live secrets in the repo.
  const outcome = evaluateGate(
    [finding({ verifyStatus: "unknown", verifyReason: "network" })],
    "verified"
  );
  assert.strictEqual(outcome.fail, true, "--fail-on verified cannot vouch for what it never checked");
  assert.ok(outcome.note, "a gate failing for something other than a live secret must say why");
});

test("a finding with no verifier does not fail the gate", () => {
  // Option C: unknown fails only where a check was possible. Otherwise
  // --fail-on verified collapses into --fail-on any and gets switched off.
  const outcome = evaluateGate([finding({ ruleId: "private-key-block" })], "verified");
  assert.strictEqual(outcome.fail, false, "never checkable is not the same as unresolved");
});

test("the gate note distinguishes an infra problem from one needing a human", () => {
  const outcome = evaluateGate(
    [
      finding({ ruleId: "a", verifyStatus: "unknown", verifyReason: "network" }),
      finding({ ruleId: "b", verifyStatus: "unknown", verifyReason: "network" }),
      finding({ ruleId: "c", verifyStatus: "unknown", verifyReason: "provider-refused" }),
    ],
    "verified"
  );
  assert.strictEqual(outcome.fail, true);
  assert.match(outcome.note!, /2/, "counts per reason");
  assert.match(outcome.note!, /could not reach the provider/i);
  assert.match(outcome.note!, /refused the check/i);
  assert.match(outcome.note!, /egress|connectivity/i, "one remedy is infrastructure");
  assert.match(outcome.note!, /inspect/i, "the other needs a person");
});

test("a live credential alone needs no explanatory note", () => {
  const outcome = evaluateGate([finding({ verifyStatus: "live" })], "verified");
  assert.strictEqual(outcome.fail, true);
  assert.strictEqual(outcome.note, undefined, "CONFIRMED LIVE in the report says it already");
});

test("unresolved checks do not affect the severity gates", () => {
  const unresolved = [finding({ severity: "low", verifyStatus: "unknown", verifyReason: "network" })];
  assert.strictEqual(evaluateGate(unresolved, "high").fail, false);
  assert.strictEqual(evaluateGate(unresolved, "critical").fail, false);
});

/** Writes a baseline file into a throwaway directory and hands over its path. */
function withBaselineFile(fingerprints: string[], fn: (file: string) => void): void {
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-cli-test-"));
  try {
    const file = path.join(dir, "baseline.json");
    writeFileSync(file, JSON.stringify({ version: 1, fingerprints }, null, 2), "utf8");
    fn(file);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

suite("\ncli.ts — baseline");

test("applyBaseline drops accepted findings and keeps the rest", () => {
  const accepted = finding({ file: "a.ts", fingerprint: "a.ts:github-token:aaa" });
  const fresh = finding({ file: "b.ts", fingerprint: "b.ts:github-token:bbb" });
  withBaselineFile(["a.ts:github-token:aaa"], (file) => {
    const kept = applyBaseline([accepted, fresh], file);
    assert.deepStrictEqual(kept.map((f) => f.fingerprint), ["b.ts:github-token:bbb"]);
  });
});

test("re-writing a baseline preserves the fingerprints already accepted", () => {
  // `--baseline old --write-baseline new` used to write only what the baseline
  // had NOT already accepted, so refreshing a baseline emptied it and the next
  // scan failed on everything.
  const fresh = [finding({ file: "b.ts", fingerprint: "b.ts:github-token:bbb" })];
  const merged = mergeBaseline(fresh, new Set(["a.ts:github-token:aaa"]));
  assert.deepStrictEqual(
    [...merged].sort(),
    ["a.ts:github-token:aaa", "b.ts:github-token:bbb"]
  );
});

test("re-writing a baseline does not duplicate an already-accepted fingerprint", () => {
  const same = [finding({ file: "a.ts", fingerprint: "a.ts:github-token:aaa" })];
  assert.deepStrictEqual(mergeBaseline(same, new Set(["a.ts:github-token:aaa"])), [
    "a.ts:github-token:aaa",
  ]);
});

test("writing a baseline with no prior baseline records the current findings", () => {
  const fresh = [finding({ file: "b.ts", fingerprint: "b.ts:github-token:bbb" })];
  assert.deepStrictEqual(mergeBaseline(fresh, new Set()), ["b.ts:github-token:bbb"]);
});

test("findings with no fingerprint are not written to the baseline", () => {
  // Raw-text scans carry no file path, so they have no stable identity.
  assert.deepStrictEqual(mergeBaseline([finding({ fingerprint: undefined })], new Set()), []);
});

test("--baseline and --write-baseline cannot name the same file", () => {
  const error = validateArgs(parseArgs(["scan", "--baseline", "b.json", "--write-baseline", "b.json"]));
  assert.ok(error, "expected the same path for both flags to be rejected");
  assert.match(error!, /--write-baseline/);
});

test("--baseline and --write-baseline naming the same file by different paths is rejected", () => {
  const error = validateArgs(
    parseArgs(["scan", "--baseline", "./b.json", "--write-baseline", "b.json"])
  );
  assert.ok(error, "paths must be compared after resolution");
});

test("--baseline and --write-baseline naming different files is accepted", () => {
  assert.strictEqual(
    validateArgs(parseArgs(["scan", "--baseline", "old.json", "--write-baseline", "new.json"])),
    null
  );
});

suite("\ncli.ts — verification ordering");

test("an already-baselined finding is never handed to the verifier", () => {
  // Verifying before baselining re-sent every already-triaged credential to its
  // provider on every CI run.
  const accepted = finding({ file: "a.ts", fingerprint: "a.ts:github-token:aaa" });
  const fresh = finding({ file: "b.ts", fingerprint: "b.ts:github-token:bbb" });
  withBaselineFile(["a.ts:github-token:aaa"], (file) => {
    const plan = triageFindings([accepted, fresh], parseArgs(["scan", "--verify", "--baseline", file]));
    assert.deepStrictEqual(plan.toVerify.map((f) => f.fingerprint), ["b.ts:github-token:bbb"]);
    assert.deepStrictEqual(plan.reported.map((f) => f.fingerprint), ["b.ts:github-token:bbb"]);
  });
});

test("nothing is queued for verification without --verify", () => {
  const plan = triageFindings([finding()], parseArgs(["scan"]));
  assert.strictEqual(plan.toVerify.length, 0);
  assert.strictEqual(plan.reported.length, 1, "the finding is still reported");
});

test("every finding is queued for verification when no baseline is given", () => {
  const plan = triageFindings([finding(), finding()], parseArgs(["scan", "--verify"]));
  assert.strictEqual(plan.toVerify.length, 2);
});

test("queued findings are the same objects that get reported", () => {
  // verifyAll marks findings in place, so the two lists must share identity or
  // the verification results never reach the report.
  const plan = triageFindings([finding()], parseArgs(["scan", "--verify"]));
  assert.strictEqual(plan.toVerify[0], plan.reported[0]);
});

suite("cli.ts — a root that cannot be scanned is an error, not a clean result");

test("a --path that does not exist is rejected", () => {
  const missing = path.join(tmpdir(), "secretloop-not-here-" + process.pid);
  const error = validateRoot(missing);
  assert.ok(error, "expected a nonexistent --path to be rejected");
  assert.match(error!, /does not exist/i);
});

test("a --path that is a file rather than a directory is rejected", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-root-"));
  try {
    const file = path.join(dir, "notes.txt");
    writeFileSync(file, "hello", "utf8");
    const error = validateRoot(file);
    assert.ok(error, "expected a file --path to be rejected");
    assert.match(error!, /not a directory/i);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a real directory is accepted", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-root-"));
  try {
    assert.strictEqual(validateRoot(dir), null);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

suite("cli.ts — describing what a scan covered");

test("an empty enumeration says so rather than reading as clean", () => {
  // "Scanned 0 file(s)." is technically true and reads as a pass. An excluded-
  // everything config and an empty rev-range both land here, and neither is a
  // clean result.
  const described = describeScope(0, "file");
  assert.match(described, /0 file\(s\)/);
  assert.match(described, /nothing was scanned/i);
});

test("a normal count is left alone", () => {
  assert.strictEqual(describeScope(412, "file"), "412 file(s)");
  assert.strictEqual(describeScope(1, "commit"), "1 commit(s)");
});

suite("\ncli.ts — refusing an unsupported Node before anything else runs");

test("an unsupported Node is named, and so is the floor it missed", () => {
  // "requires Node >=X" on its own leaves the reader checking their version by
  // hand, which is the moment a cryptic error was already going to cost them.
  for (const running of ["16.20.2", "14.21.3"]) {
    const message = checkNodeVersion(running);
    assert.ok(message, `${running} is below the floor and must be refused`);
    assert.ok(
      message!.includes(MIN_NODE),
      `must name the floor it needs — got: ${message}`
    );
    assert.ok(
      message!.includes(running),
      `must name the version actually running — got: ${message}`
    );
    assert.match(message!, /require/i, message!);
  }
});

test("exactly the floor is supported", () => {
  // An off-by-one here refuses the very version the package declares support
  // for, which is worse than not guarding at all.
  assert.strictEqual(checkNodeVersion("18.0.0"), null);
});

test("the last version below the floor is refused", () => {
  const message = checkNodeVersion("17.9.9");
  assert.ok(message, "17.9.9 has no global fetch");
  assert.ok(message!.includes("17.9.9"));
});

test("later majors pass through silently", () => {
  for (const running of ["18.20.4", "20.11.1", "24.19.0"]) {
    assert.strictEqual(checkNodeVersion(running), null, running);
  }
});

test("a version string it cannot read fails open rather than crashing", () => {
  // Deliberate: a guard that throws — or refuses — on a version string it does
  // not recognise is worse than no guard. It would block a runtime that may be
  // perfectly fine, and the failure it produced would be exactly the cryptic
  // one it exists to prevent.
  for (const weird of ["", "unknown"]) {
    assert.strictEqual(
      checkNodeVersion(weird),
      null,
      `${JSON.stringify(weird)} must be let through, not guessed at`
    );
  }
});


suite("\ncli.ts — #8: a flag given the wrong value, or none");

/** Parse errors only, so a test never has to reach into an optional field. */
function errorsFor(argv: string[]): string[] {
  return parseArgs(argv).errors ?? [];
}

/** Exactly one error, returned, so each assertion can say what it wanted. */
function oneError(argv: string[]): string {
  const errors = errorsFor(argv);
  assert.strictEqual(errors.length, 1, `expected one error from ${argv.join(" ")}, got ${errors.length}: ${errors.join(" | ")}`);
  return errors[0];
}

/** Every flag that consumes the next token. -o is the alias for --output. */
const VALUE_FLAGS = [
  "--format",
  "--baseline",
  "--write-baseline",
  "--output",
  "-o",
  "--max-commits",
  "--rev-range",
  "--path",
  "--fail-on",
];

test("a value-taking flag at the end of argv is rejected, not silently dropped", () => {
  // next() is argv[++i] with no bounds check, so today each of these becomes
  // undefined and the flag quietly does nothing: --output writes no file,
  // --write-baseline writes no baseline, --format falls back to text.
  for (const flag of VALUE_FLAGS) {
    const message = oneError(["scan", flag]);
    assert.ok(message.includes(flag), `must name the flag — got: ${message}`);
    assert.match(message, /requires a value|missing/i, message);
  }
});

test("a flag swallowed as another flag's value is rejected, naming both", () => {
  // `--format --verify` is the dangerous one: --verify becomes the format
  // string, verification never runs, and the report says so in a line nobody
  // re-reads.
  const format = oneError(["scan", "--format", "--verify"]);
  assert.ok(format.includes("--format"), format);
  assert.ok(format.includes("--verify"), `must name the token it swallowed — got: ${format}`);
  // The token is reported but NOT consumed, so it still parses as itself.
  // A consuming and a non-consuming implementation both yield exactly one
  // error, so this is the only assertion that pins which one happened.
  assert.strictEqual(
    parseArgs(["scan", "--format", "--verify"]).verify,
    true,
    "--verify must still take effect after being reported as a bad value"
  );

  const output = oneError(["scan", "-o", "--verify"]);
  assert.ok(output.includes("-o"), output);
  assert.ok(output.includes("--verify"), output);
});

test("--max-commits -5 is a bad number, not a missing value", () => {
  // It sits on the seam: -5 is flag-shaped, so a blanket "values must not start
  // with -" rule would report the wrong fault. The message has to fit what is
  // actually wrong with it.
  const message = oneError(["history", "--max-commits", "-5"]);
  assert.ok(message.includes("--max-commits"), message);
  assert.ok(message.includes("-5"), message);
  assert.match(message, /positive integer/i, message);
  assert.doesNotMatch(message, /requires a value|missing/i, message);
});

test("an invalid enum value names the flag and the value it was given", () => {
  // Today --format foo renders text through render()'s default branch, so
  // `--format sariff -o results.sarif` writes a text file that upload-sarif
  // cannot read; --fail-on potato lands on evaluateGate's default and silently
  // becomes the strictest mode.
  const format = oneError(["scan", "--format", "foo"]);
  assert.ok(format.includes("--format"), format);
  assert.ok(format.includes("foo"), format);

  const failOn = oneError(["scan", "--fail-on", "potato"]);
  assert.ok(failOn.includes("--fail-on"), failOn);
  assert.ok(failOn.includes("potato"), failOn);
});

test("every documented enum value is still accepted", () => {
  // No-change guard: rejection must not narrow what already works.
  for (const format of ["text", "json", "sarif"]) {
    assert.deepStrictEqual(errorsFor(["scan", "--format", format]), [], format);
    assert.strictEqual(parseArgs(["scan", "--format", format]).format, format);
  }
  for (const failOn of ["any", "verified", "critical", "high", "never"]) {
    assert.deepStrictEqual(errorsFor(["scan", "--fail-on", failOn]), [], failOn);
    assert.strictEqual(parseArgs(["scan", "--fail-on", failOn]).failOn, failOn);
  }
});

test("--max-commits rejects what git cannot use as a limit", () => {
  // banana is NaN and 0 is falsy, so `if (options.maxCommits)` drops both and
  // the scan silently covers the whole history. -5 reaches git as `-n-5`, which
  // git treats as no limit at all — verified against a 53-commit repository.
  for (const value of ["banana", "0", "-5"]) {
    const message = oneError(["history", "--max-commits", value]);
    assert.ok(message.includes("--max-commits"), message);
    assert.ok(message.includes(value), `must quote back what it was given — got: ${message}`);
  }
});

test("--max-commits still accepts a real limit", () => {
  // No-change guard, and the one that proves the rejection is not blanket:
  // --max-commits 2 correctly scans 2 of 53 commits today.
  for (const value of ["1", "2", "500"]) {
    assert.deepStrictEqual(errorsFor(["history", "--max-commits", value]), [], value);
    assert.strictEqual(parseArgs(["history", "--max-commits", value]).maxCommits, Number(value));
  }
});

test("validateArgs surfaces a parse error, so a bad flag exits 2 like any usage error", () => {
  const error = validateArgs(parseArgs(["scan", "--format", "foo"]));
  assert.ok(error, "a parse error must reach the usage-error path");
  assert.ok(error!.includes("--format"), error!);
});

test("a parse error is reported ahead of the combination rules", () => {
  // Both are wrong here. The one that makes the command unrunnable at all is
  // the one worth printing first.
  const error = validateArgs(parseArgs(["scan", "--fail-on", "verified", "--format", "foo"]));
  assert.ok(error, "expected an error");
  assert.ok(error!.includes("--format"), `the parse error should win — got: ${error}`);
});

suite("\ncli.ts — #9: a token SecretLoop does not recognise");

test("an unknown option is rejected, naming the token", () => {
  // The switch has no default case, so today every one of these is dropped and
  // the user gets a scan that quietly ignored what they asked for.
  for (const argv of [
    ["scan", "--fail-onn", "critical"],
    ["scan", "--verifyy"],
    ["scan", "--outputt", "results.json"],
  ]) {
    const errors = errorsFor(argv);
    assert.ok(errors.length > 0, `${argv.join(" ")} must be rejected`);
    assert.ok(
      errors.some((e) => e.includes(argv[1])),
      `must name ${argv[1]} — got: ${errors.join(" | ")}`
    );
    assert.match(errors[0], /unknown option/i, errors[0]);
  }
});

test("an unknown command is rejected, naming it", () => {
  // `secretloop hisotry` scans the working tree and reports "Scanned 54
  // file(s)" while the history it was asked about goes unlooked-at.
  for (const word of ["hisotry", "scna", "stagd"]) {
    const message = oneError([word]);
    assert.ok(message.includes(word), message);
    assert.match(message, /unknown command/i, message);
  }
});

test("the four real commands stay clean", () => {
  // No-change guard.
  for (const word of ["scan", "staged", "history", "help"]) {
    assert.deepStrictEqual(errorsFor([word]), [], word);
    assert.strictEqual(parseArgs([word]).command, word);
  }
});

test("a flag's value is never mistaken for an unknown command", () => {
  // The landmine. The positional pre-pass is argv.filter(a => !a.startsWith("-")),
  // which cannot tell a command from a value: for `secretloop --format json`,
  // positional[0] is "json". Unknown-token detection has to work from the tokens
  // the main loop did not consume as values, never from that filter.
  assert.deepStrictEqual(errorsFor(["--format", "json"]), [], "json is a format, not a command");
  assert.deepStrictEqual(errorsFor(["--baseline", "b.json"]), [], "b.json is a file, not a command");
  assert.deepStrictEqual(
    errorsFor(["history", "--rev-range", "origin/main..HEAD"]),
    [],
    "a rev range is not a command"
  );
  // And the command each of those actually resolves to is unchanged.
  assert.strictEqual(parseArgs(["--format", "json"]).command, "scan");
  assert.strictEqual(parseArgs(["--format", "json"]).format, "json");
});

test("asking for help anywhere in argv is help, with nothing to complain about", () => {
  // No-change guard. Someone reaching for --help is not asking to be told their
  // other arguments are wrong.
  for (const argv of [["-h"], ["--help"], ["scan", "--format", "-h"], ["hisotry", "--help"]]) {
    assert.strictEqual(parseArgs(argv).command, "help", argv.join(" "));
    assert.deepStrictEqual(errorsFor(argv), [], argv.join(" "));
  }
});


finish();
