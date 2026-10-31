import {
  applyBaseline,
  mergeBaseline,
  parseArgs,
  evaluateGate,
  triageFindings,
  validateArgs,
  validateRoot,
  describeScope,
  sanitizeForDisplay,
  runApprove,
  ApproveIO,
  HELP,
} from "../src/cli";
import * as consent from "../src/consent";
import { loadConfig } from "../src/config";
import { checkNodeVersion, MIN_NODE } from "../src/node-guard";
import { Finding, scanText } from "../src/scanner";
import { test, suite, finish, assert, skip } from "./harness";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "fs";
import { spawnSync } from "child_process";
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


suite("\ncli.ts — --verify and --write-baseline are not a combination");

/**
 * The combination sent every credential to its provider and threw the verdicts
 * away.
 *
 * --write-baseline accepts every current finding and returns before the report
 * is rendered, so the verification pass ran, the credentials left the machine,
 * and nothing was ever printed about what came back. Not a leak and not a lie
 * -- the outbound record counted every call honestly -- just network traffic
 * with a user's live credentials in it, in service of nothing.
 *
 * Rejected rather than reordered or silently skipped, matching the two rules
 * already in validateArgs: which runnable combinations make sense is a question
 * for the command line, not something to resolve on the user's behalf when the
 * resolution involves transmitting credentials.
 */

/** The parser's own defaults, so a case here differs from a real run in one field. */
function baseArgs() {
  return parseArgs(["scan"]);
}

const CLI_PATH = path.join(__dirname, "..", "out", "cli.js");
const VERIFIABLE = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";

test("validateArgs rejects them together, and neither alone", () => {
  const both = validateArgs({ ...baseArgs(), verify: true, writeBaseline: "/tmp/b.json" });
  assert.ok(both, "--verify --write-baseline was accepted");
  assert.match(both!, /--verify/);
  assert.match(both!, /--write-baseline/);

  assert.strictEqual(validateArgs({ ...baseArgs(), verify: true }), null, "--verify alone still works");
  assert.strictEqual(
    validateArgs({ ...baseArgs(), writeBaseline: "/tmp/b.json" }),
    null,
    "--write-baseline alone still works"
  );
});

/**
 * A fetch that records what it was asked for and answers without a socket.
 *
 * Recording alone is not enough: calling through would send a fixture
 * credential to GitHub, which this suite must never do. The shim answers 401
 * itself, so the assertion is about what the CLI tried to send and nothing
 * leaves the machine either way.
 */
function withFetchSpy(
  fn: (run: (args: string[]) => { status: number | null; stdout: string; stderr: string; sent: string[] }) => void
): void {
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-spy-"));
  try {
    const spyFile = path.join(dir, "sent.log");
    const shim = path.join(dir, "shim.js");
    writeFileSync(
      shim,
      [
        'const fs = require("fs");',
        "globalThis.fetch = async (input) => {",
        '  fs.appendFileSync(process.env.SECRETLOOP_SPY, String(input) + "\\n");',
        '  return new Response("{}", { status: 401 });',
        "};",
      ].join("\n"),
      "utf8"
    );
    const run = (args: string[]) => {
      rmSync(spyFile, { force: true });
      const res = spawnSync("node", [CLI_PATH, ...args], {
        encoding: "utf8",
        env: {
          ...process.env,
          NODE_OPTIONS: `${process.env.NODE_OPTIONS ?? ""} --require ${shim}`.trim(),
          SECRETLOOP_SPY: spyFile,
        },
      });
      const sent = existsSync(spyFile)
        ? readFileSync(spyFile, "utf8").split("\n").filter(Boolean)
        : [];
      return { status: res.status, stdout: res.stdout, stderr: res.stderr, sent };
    };
    fn(run);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("the combination exits 2, sends nothing, and writes no baseline", () => {
  withFetchSpy((run) => {
    const repo = mkdtempSync(path.join(tmpdir(), "secretloop-wb-"));
    try {
      writeFileSync(path.join(repo, "app.js"), `const t = "${VERIFIABLE}";\n`, "utf8");
      const baseline = path.join(repo, "baseline.json");

      // The control first, so the spy is known to work. Without it "nothing was
      // sent" is a claim about a shim that might never have been installed.
      const verifying = run(["scan", "--path", repo, "--verify"]);
      assert.ok(
        verifying.sent.some((u) => u.includes("api.github.com")),
        `the spy recorded nothing for --verify alone: ${JSON.stringify(verifying.sent)}`
      );

      const both = run(["scan", "--path", repo, "--verify", "--write-baseline", baseline]);
      assert.strictEqual(both.status, 2, `expected exit 2, got ${both.status}: ${both.stderr}`);
      assert.match(both.stderr, /--verify/);
      assert.match(both.stderr, /--write-baseline/);
      assert.deepStrictEqual(
        both.sent,
        [],
        `a refused run still contacted a provider: ${JSON.stringify(both.sent)}`
      );
      assert.strictEqual(both.stdout, "", "a refused run printed a report");
      assert.ok(!existsSync(baseline), "a refused run wrote the baseline anyway");
    } finally {
      rmSync(repo, { recursive: true, force: true });
    }
  });
});

test("--write-baseline alone still writes, without contacting anyone", () => {
  withFetchSpy((run) => {
    const repo = mkdtempSync(path.join(tmpdir(), "secretloop-wb2-"));
    try {
      writeFileSync(path.join(repo, "app.js"), `const t = "${VERIFIABLE}";\n`, "utf8");
      const baseline = path.join(repo, "baseline.json");
      const res = run(["scan", "--path", repo, "--write-baseline", baseline]);
      assert.strictEqual(res.status, 0, `expected exit 0, got ${res.status}: ${res.stderr}`);
      assert.ok(existsSync(baseline), "the baseline was not written");
      assert.deepStrictEqual(res.sent, [], "writing a baseline contacted a provider");
      const written = JSON.parse(readFileSync(baseline, "utf8"));
      assert.ok(written.fingerprints.length > 0, "the baseline is empty");
    } finally {
      rmSync(repo, { recursive: true, force: true });
    }
  });
});

suite("\ncli.ts — --version");

// The version the CLI prints has to be the one npm published, so the expected
// value is read from package.json rather than written out here. A literal would
// pass for the wrong reason the moment the package version moves.
const PKG_VERSION: string = JSON.parse(
  readFileSync(path.join(__dirname, "..", "package.json"), "utf8")
).version;

test("--version prints the canonical package version and exits 0", () => {
  const res = spawnSync("node", [CLI_PATH, "--version"], { encoding: "utf8" });
  assert.strictEqual(res.status, 0, `expected exit 0, got ${res.status}: ${res.stderr}`);
  // Exact equality, not a match: it proves the byte after the version is the
  // newline and nothing else -- no banner, no scan summary, no trailing space.
  assert.strictEqual(
    res.stdout,
    `${PKG_VERSION}\n`,
    `stdout was ${JSON.stringify(res.stdout)}`
  );
  assert.strictEqual(res.stderr, "", `stderr was ${JSON.stringify(res.stderr)}`);
});

test("--version does not start a scan", () => {
  // Run it inside a directory that holds a credential. A scan would report the
  // finding and exit 1; printing the version must do neither.
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-ver-"));
  try {
    writeFileSync(path.join(dir, "app.js"), `const t = "${VERIFIABLE}";\n`, "utf8");
    const res = spawnSync("node", [CLI_PATH, "--version"], { encoding: "utf8", cwd: dir });
    assert.strictEqual(res.status, 0, `expected exit 0, got ${res.status}: ${res.stderr}`);
    assert.strictEqual(res.stdout, `${PKG_VERSION}\n`, "a scan report reached stdout");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("--version adds no alias and no positional command", () => {
  // The request was for --version specifically. -V and a bare `version` word
  // stay unknown, so this flag does not quietly widen the CLI surface.
  assert.strictEqual(parseArgs(["--version"]).command, "version");
  assert.ok(parseArgs(["-V"]).errors?.some((e) => /unknown option -V/.test(e)), "-V became an alias");
  assert.ok(
    parseArgs(["version"]).errors?.some((e) => /unknown command version/.test(e)),
    "`version` became a positional command"
  );
});

suite("cli.ts — --include-entropy precedence");

/**
 * The six precedence cases, run end to end against the built CLI rather than
 * against parseArgs, because the property under test is the effective config a
 * scan runs under -- which is assembled in main(), not in the parser.
 *
 * The fixture is a high-entropy string matching no provider format, so the ONLY
 * thing that can report it is the generic tier.
 */
const ENTROPY_ONLY = 'value = "Zk9pQ2xR8mLtW3vXyB7nD1sF4jH6uK0eA5"\n';

function entropyFindings(projectConfig: object | null, args: string[]): number {
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-ent-"));
  try {
    writeFileSync(path.join(dir, "app.js"), ENTROPY_ONLY, "utf8");
    if (projectConfig !== null) {
      writeFileSync(path.join(dir, ".secretloop.json"), JSON.stringify(projectConfig), "utf8");
    }
    const res = spawnSync(
      "node",
      [CLI_PATH, "scan", ".", "--format", "json", "--fail-on", "never", ...args],
      { encoding: "utf8", cwd: dir }
    );
    assert.strictEqual(res.status, 0, `exit ${res.status}: ${res.stderr}`);
    const report = JSON.parse(res.stdout) as { findings: Array<{ ruleId: string }> };
    return report.findings.filter((f) => f.ruleId === "generic-high-entropy").length;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("no config + no flag -> OFF", () => {
  assert.strictEqual(entropyFindings(null, []), 0);
});

test("config true + no flag -> ON", () => {
  assert.strictEqual(entropyFindings({ entropyPassEnabled: true }, []), 1);
});

test("config false + no flag -> OFF", () => {
  assert.strictEqual(entropyFindings({ entropyPassEnabled: false }, []), 0);
});

test("no config + --include-entropy -> ON", () => {
  assert.strictEqual(entropyFindings(null, ["--include-entropy"]), 1);
});

test("config false + --include-entropy -> ON", () => {
  // The flag beats an explicit project `false`. Raise-only is the whole rule.
  assert.strictEqual(entropyFindings({ entropyPassEnabled: false }, ["--include-entropy"]), 1);
});

test("config true + --include-entropy -> ON", () => {
  assert.strictEqual(entropyFindings({ entropyPassEnabled: true }, ["--include-entropy"]), 1);
});

test("--include-entropy is accepted by scan, staged and history", () => {
  // Behavioral check, not parser reuse: these are the commands that reach the
  // loadConfig path in main(). `mask` and `approve` return before it.
  for (const command of ["scan", "staged", "history"]) {
    const args = parseArgs([command, "--include-entropy"]);
    assert.strictEqual(args.includeEntropy, true, `${command} did not accept the flag`);
    assert.strictEqual(args.errors, undefined, `${command} reported ${JSON.stringify(args.errors)}`);
  }
});

test("--include-entropy is distinct from mask's --entropy", () => {
  // Two switches, two scopes. Neither implies the other.
  assert.strictEqual(parseArgs(["scan", "--include-entropy"]).entropy, false);
  assert.strictEqual(parseArgs(["mask", "--entropy"]).includeEntropy, false);
  assert.ok(HELP.includes("--include-entropy"), "the scan flag is undocumented");
  assert.ok(HELP.includes("mask ONLY:"), "mask's --entropy no longer names its scope");
});

suite("cli.ts — credential groups in the JSON report, end to end");

/**
 * The built CLI, a real scan and the real JSON path. Both values are generic high-entropy strings matching no provider
 * format, assembled here so the literal never sits in source; only the generic tier reports them, and nothing is
 * verified.
 */
const GROUPED_A = "Zk9pQ2xR8mLt" + "W3vXyB7nD1sF4jH6uK0eA5";
const GROUPED_B = "Qm4tR7vXc2Lp" + "W9nBy5KdF8sJ1hU6eA3zG0";

interface GroupedReport {
  schemaVersion: number;
  summary: { total: number; credentialGroupCount: number; groupedFindingCount: number };
  findings: Array<{ id: string; file: string; ruleId: string }>;
  credentialGroups: Array<{ id: string; ruleId: string; findings: string[]; occurrences: number }>;
}

function scanGrouped(dir: string, extra: string[] = []): { report: GroupedReport; stdout: string } {
  const res = spawnSync(
    "node",
    [CLI_PATH, "scan", ".", "--format", "json", "--fail-on", "never", "--include-entropy", ...extra],
    { encoding: "utf8", cwd: dir }
  );
  assert.strictEqual(res.status, 0, `exit ${res.status}: ${res.stderr}`);
  return { report: JSON.parse(res.stdout) as GroupedReport, stdout: res.stdout };
}

function plant(dir: string, rel: string, value: string): void {
  mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
  writeFileSync(path.join(dir, rel), `value = "${value}"\n`, "utf8");
}

const filesOf = (report: GroupedReport, ids: string[]) => ids.map((id) => report.findings.find((f) => f.id === id)?.file);

test("one credential in three files is one group naming the three findings the report emits", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-groups-"));
  try {
    plant(dir, "config/dev.js", GROUPED_A);
    plant(dir, "src/settings.js", GROUPED_A);
    plant(dir, "deploy/app.js", GROUPED_A);
    plant(dir, "other.js", GROUPED_B);
    const { report, stdout } = scanGrouped(dir);
    assert.strictEqual(report.summary.total, 4, "every occurrence is still its own finding");
    assert.strictEqual(report.schemaVersion, 5, "an additive descriptive field does not move the schema version");
    assert.strictEqual(report.credentialGroups.length, 1, "the second credential appears once and has no group");
    const [g] = report.credentialGroups;
    assert.strictEqual(g.id, "G1");
    assert.strictEqual(g.ruleId, "generic-high-entropy");
    assert.strictEqual(g.occurrences, 3);
    assert.deepStrictEqual(filesOf(report, g.findings), ["config/dev.js", "deploy/app.js", "src/settings.js"]);
    assert.strictEqual(report.summary.credentialGroupCount, 1);
    assert.strictEqual(report.summary.groupedFindingCount, 3);
    assert.ok(!stdout.includes(GROUPED_A) && !stdout.includes(GROUPED_B), "a raw value reached the report");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a baselined occurrence leaves the group, and the group names only findings still reported", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-groups-"));
  const store = mkdtempSync(path.join(tmpdir(), "secretloop-groups-baseline-"));
  const baseline = path.join(store, "baseline.json");
  try {
    plant(dir, "config/dev.js", GROUPED_A);
    const write = spawnSync("node", [CLI_PATH, "scan", ".", "--include-entropy", "--write-baseline", baseline], {
      encoding: "utf8",
      cwd: dir,
    });
    assert.strictEqual(write.status, 0, `exit ${write.status}: ${write.stderr}`);
    plant(dir, "src/settings.js", GROUPED_A);
    plant(dir, "deploy/app.js", GROUPED_A);
    const { report } = scanGrouped(dir, ["--baseline", baseline]);
    assert.deepStrictEqual(report.findings.map((f) => f.file), ["deploy/app.js", "src/settings.js"], "the baseline applied");
    assert.strictEqual(report.credentialGroups.length, 1);
    assert.strictEqual(report.credentialGroups[0].occurrences, 2, "the accepted occurrence is not counted");
    assert.deepStrictEqual(filesOf(report, report.credentialGroups[0].findings), ["deploy/app.js", "src/settings.js"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
    rmSync(store, { recursive: true, force: true });
  }
});

suite("\ncli.ts — an error message shows repository text, it never acts on it");

/*
 * Errors reach stderr -- a terminal, the pre-commit hook's output, a CI log -- and several carried outside text raw:
 * main()'s catch printed a configuration error that quotes a repository's .secretloop.json (an invalid allowValues
 * pattern), the root check printed the path it was given, the staged scan printed git's stderr, and argument and
 * --rev-range refusals echoed what was typed. ESC drove the terminal, a bidi override rewrote the line and a newline
 * printed lines of its own (a CI command, a fake "secretloop:" line). Each is now shown through the text report's
 * escaping; the message, its wording and the exit code are otherwise unchanged.
 */
const C = (n: number) => String.fromCharCode(n);
const ESC = C(27), RLO = C(0x202e), LF = "\n";
const HOSTILE = "x" + ESC + "[31mRED" + RLO + LF + "::stop-commands::tok" + LF + "secretloop: No secrets found";

function activeIn(text: string): boolean {
  for (const ch of text) {
    const n = ch.charCodeAt(0);
    if ((n < 0x20 && n !== 0x0a) || (n >= 0x7f && n <= 0x9f) || n === 0x61c || n === 0x200e || n === 0x200f ||
        (n >= 0x202a && n <= 0x202e) || (n >= 0x2066 && n <= 0x2069) || n === 0x2028 || n === 0x2029) return true;
  }
  return false;
}

function cliIn(cwd: string, args: string[], env: NodeJS.ProcessEnv = process.env) {
  return spawnSync("node", [CLI_PATH, ...args], { cwd, encoding: "utf8", env, timeout: 60000 });
}

/** stderr says what it said before, once, with nothing a terminal or CI runner would act on. */
function assertShownOnce(stderr: string, mustContain: string, what: string): void {
  assert.ok(!activeIn(stderr), `${what}: an active character reached stderr`);
  const lines = stderr.split("\n").filter((l) => l.length > 0);
  assert.strictEqual(lines.length, 1, `${what}: the message printed ${lines.length} lines`);
  assert.ok(lines[0].startsWith("secretloop: "), `${what}: ${JSON.stringify(lines[0])}`);
  assert.ok(lines[0].includes(mustContain), `${what}: the message lost its wording`);
  assert.ok(!lines.some((l) => /^\s*::/.test(l)), `${what}: a line starts as a CI workflow command`);
}

function withDir(fn: (dir: string) => void): void {
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-stderr-"));
  try {
    fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const gitIn = (dir: string, ...a: string[]) =>
  spawnSync("git", ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", ...a], { cwd: dir, encoding: "utf8" });

test("a repository's invalid allowValues pattern is shown escaped by scan and by staged, exit 2", () => {
  withDir((dir) => {
    writeFileSync(path.join(dir, ".secretloop.json"), JSON.stringify({ allowValues: ["(" + HOSTILE] }), "utf8");
    writeFileSync(path.join(dir, "a.js"), "const ok = 1;\n", "utf8");
    gitIn(dir, "init", "-q");
    gitIn(dir, "add", "-A");
    for (const cmd of [["scan", "."], ["staged"]]) {
      const r = cliIn(dir, [...cmd, "--fail-on", "never"]);
      assert.strictEqual(r.status, 2, `${cmd[0]} exit`);
      assertShownOnce(r.stderr, "is not a valid regular expression", cmd[0]);
      assert.ok(r.stderr.includes("\\x1b[31mRED\\u202e"), `${cmd[0]}: the pattern is not shown escaped`);
    }
  });
});

test("a --path that does not exist is shown escaped, exit 2", () => {
  withDir((dir) => {
    const r = cliIn(dir, ["scan", "--path", path.join(dir, "no" + HOSTILE), "--fail-on", "never"]);
    assert.strictEqual(r.status, 2);
    assertShownOnce(r.stderr, "does not exist.", "rootError");
  });
});

test("an argument error and a refused --rev-range echo what was typed escaped, exit 2", () => {
  withDir((dir) => {
    gitIn(dir, "init", "-q");
    const bad = cliIn(dir, ["scan", "--format", "json" + HOSTILE]);
    assert.strictEqual(bad.status, 2);
    assertShownOnce(bad.stderr, "is not a known format", "argError");
    const range = cliIn(dir, ["history", "--rev-range", "main" + HOSTILE]);
    assert.strictEqual(range.status, 2);
    assertShownOnce(range.stderr, "was refused", "--rev-range");
  });
});

test("git's stderr from the staged listing is shown escaped, exit 2", () => {
  if (process.platform === "win32") skip("a shell-script git stand-in is POSIX only");
  withDir((dir) => {
    const realGit = spawnSync("sh", ["-c", "command -v git"], { encoding: "utf8" }).stdout.trim();
    assert.ok(realGit, "git not found");
    const bin = path.join(dir, "bin");
    mkdirSync(bin);
    // Stands in for git only for the staged listing, writing hostile text to stderr; every other call is real git.
    writeFileSync(path.join(bin, "git"), `#!/bin/sh\nfor a in "$@"; do if [ "$a" = "--cached" ]; then printf '%s' "$SECRETLOOP_TEST_STDERR" >&2; exit 128; fi; done\nexec "${realGit}" "$@"\n`, { mode: 0o755 });
    const repo = path.join(dir, "repo");
    mkdirSync(repo);
    gitIn(repo, "init", "-q");
    const env = { ...process.env, PATH: `${bin}${path.delimiter}${process.env.PATH}`, SECRETLOOP_TEST_STDERR: "fatal: " + HOSTILE };
    const r = cliIn(repo, ["staged", "--fail-on", "never"], env);
    assert.strictEqual(r.status, 2);
    assertShownOnce(r.stderr, "git could not list staged files: fatal: x", "staged.error");
  });
});

test("a committed baseline's own version field and name are shown escaped in the outdated notice", () => {
  withDir((dir) => {
    writeFileSync(path.join(dir, "a.js"), "const ok = 1;\n", "utf8");
    const baseline = path.join(dir, "baseline.json");
    writeFileSync(baseline, JSON.stringify({ version: "1" + HOSTILE, fingerprints: [] }), "utf8");
    const r = cliIn(dir, ["scan", ".", "--baseline", baseline, "--fail-on", "never"]);
    assert.strictEqual(r.status, 0, r.stderr);
    assertShownOnce(r.stderr, "baseline and this is version", "baseline notice");
  });
});

test("an ordinary multi-line git error is kept whole, on one line, its breaks shown as \\x0a", () => {
  if (process.platform === "win32") skip("a shell-script git stand-in is POSIX only");
  withDir((dir) => {
    const realGit = spawnSync("sh", ["-c", "command -v git"], { encoding: "utf8" }).stdout.trim();
    const bin = path.join(dir, "bin");
    mkdirSync(bin);
    writeFileSync(path.join(bin, "git"), `#!/bin/sh\nfor a in "$@"; do if [ "$a" = "--cached" ]; then printf '%s' "$SECRETLOOP_TEST_STDERR" >&2; exit 128; fi; done\nexec "${realGit}" "$@"\n`, { mode: 0o755 });
    const repo = path.join(dir, "repo");
    mkdirSync(repo);
    gitIn(repo, "init", "-q");
    const env = { ...process.env, PATH: `${bin}${path.delimiter}${process.env.PATH}`, SECRETLOOP_TEST_STDERR: "fatal: a\nhint: b\n" };
    const r = cliIn(repo, ["staged", "--fail-on", "never"], env);
    assert.strictEqual(r.status, 2);
    assert.strictEqual(r.stderr, "secretloop: git could not list staged files: fatal: a\\x0ahint: b\n");
  });
});

test("a --output and a --write-baseline path are echoed escaped", () => {
  if (process.platform === "win32") skip("Windows forbids control characters in file names");
  withDir((dir) => {
    writeFileSync(path.join(dir, "a.js"), "pass" + 'word = "Qm7vR2xKp9Lw4Tz8Hc3N"\n', "utf8");
    const name = "r" + ESC + "[2K" + RLO + ".txt";
    const out = cliIn(dir, ["scan", ".", "--output", path.join(dir, name)]);
    assert.strictEqual(out.status, 1, out.stderr);
    assert.ok(!activeIn(out.stderr), "the --output path reached stderr raw");
    assert.ok(out.stderr.includes("r\\x1b[2K\\u202e.txt"), "the --output path is not shown escaped");
    const wb = cliIn(dir, ["scan", ".", "--write-baseline", path.join(dir, "b" + ESC + ".json")]);
    assert.strictEqual(wb.status, 0, wb.stderr);
    assert.ok(!activeIn(wb.stdout), "the --write-baseline path reached stdout raw");
    assert.ok(wb.stdout.includes("b\\x1b.json"), "the --write-baseline path is not shown escaped");
  });
});

test("an ordinary error is printed exactly as before", () => {
  withDir((dir) => {
    const missing = path.join(dir, "plain-missing");
    const r = cliIn(dir, ["scan", "--path", missing, "--fail-on", "never"]);
    assert.strictEqual(r.status, 2);
    assert.strictEqual(r.stderr, `secretloop: ${missing} does not exist.\n`);
  });
});

// The approval prompt prints a file name from the scanned repository. A control
// that a terminal acts on must not reach it; each one becomes "?", the same
// convention as the C0 controls.
suite("approval prompt sanitizer");

const hex = (c: string) => `U+${c.charCodeAt(0).toString(16).padStart(4, "0")}`;

test("C1 controls are replaced, including the single-character CSI at U+009B", () => {
  for (const c of ["\u0080", "\u0085", "\u009b", "\u009f"]) {
    assert.strictEqual(sanitizeForDisplay(`a${c}b`), "a?b", `${hex(c)} was printed as is`);
  }
});

test("bidi formatting controls are replaced so a name cannot reorder what is shown", () => {
  const bidi = ["\u061c", "\u200e", "\u200f", "\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069"];
  for (const c of bidi) {
    assert.strictEqual(sanitizeForDisplay(`x${c}y`), "x?y", `${hex(c)} was printed as is`);
  }
});

test("the line and paragraph separators U+2028 and U+2029 are replaced", () => {
  for (const c of ["\u2028", "\u2029"]) {
    assert.strictEqual(sanitizeForDisplay(`a${c}b`), "a?b", `${hex(c)} was printed as is`);
  }
});

test("ordinary ASCII and non-Latin file names print unchanged", () => {
  for (const name of ["config/app.js", "src/café/データ/ファイル.ts", "naïve résumé.txt"]) {
    assert.strictEqual(sanitizeForDisplay(name), name);
  }
});

test("escape sequences are removed whole and bare control bytes become ?", () => {
  assert.strictEqual(sanitizeForDisplay("a\u001b[2K\u001b[1Gb"), "ab");
  assert.strictEqual(sanitizeForDisplay("a\u0007b\u0000c\u007fd"), "a?b?c?d");
});

test("text longer than the cap is cut and says how long it was", () => {
  const long = "a".repeat(200);
  assert.strictEqual(sanitizeForDisplay(long), `${"a".repeat(160)}... (200 characters, truncated)`);
});

test("a lone surrogate is replaced", () => {
  const high = String.fromCharCode(0xd83d);
  const low = String.fromCharCode(0xde00);
  assert.strictEqual(sanitizeForDisplay(`a${high}b`), "a?b", "a lone high surrogate was printed as is");
  assert.strictEqual(sanitizeForDisplay(`a${low}b`), "a?b", "a lone low surrogate was printed as is");
});

test("a valid surrogate pair is kept whole", () => {
  const emoji = String.fromCodePoint(0x1f600);
  assert.strictEqual(sanitizeForDisplay(`a${emoji}b`), `a${emoji}b`);
  // Exactly at the cap: 158 units plus the pair's two units is 160, so nothing is cut.
  const atCap = "a".repeat(158) + emoji;
  assert.strictEqual(sanitizeForDisplay(atCap), atCap);
});

test("truncation never leaves a lone high surrogate at the cut", () => {
  const emoji = String.fromCodePoint(0x1f600);
  // The pair starts at unit 160 and the cap falls between its two halves.
  const out = sanitizeForDisplay("a".repeat(159) + emoji + "tail");
  const body = out.split("... (")[0];
  assert.strictEqual(body, "a".repeat(159), `unexpected truncated body: ${JSON.stringify(body)}`);
  const last = body.charCodeAt(body.length - 1);
  assert.ok(!(last >= 0xd800 && last <= 0xdbff), "a lone high surrogate was left at the cut");
});

suite("approval prompt, end to end");

test("runApprove prints a file name with a bidi override with the override replaced", async () => {
  const RLO = String.fromCharCode(0x202e);
  const base = mkdtempSync(path.join(tmpdir(), "sl-approve-bidi-"));
  try {
    const root = path.join(base, "repo");
    mkdirSync(root);
    const cred = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";
    const name = `rev${RLO}exe.js`;
    writeFileSync(path.join(root, name), `const t = "${cred}";\n`, "utf8");
    const config = loadConfig(root);
    const finding = scanText(readFileSync(path.join(root, name), "utf8"), { config, filePath: name }).find(
      (f) => f.ruleId === "github-token"
    );
    assert.ok(finding, "the fixture produced no github-token finding");
    const fingerprint = String(finding.fingerprint);
    consent.setConsentRootForTests(path.join(base, "store"));
    consent.writeRecord({
      version: consent.CONSENT_VERSION,
      id: consent.recordId(fingerprint, root),
      state: "pending",
      fingerprint,
      path: root,
      file: name,
      line: 1,
      ruleId: "github-token",
      provider: "GitHub",
      commitment: consent.commitmentOf(cred),
      createdAt: new Date().toISOString(),
    });
    const outs: string[] = [];
    // Answer "n": the prompt is printed and nothing is sent.
    const io: ApproveIO = { isTTY: true, out: (m) => outs.push(m), err: () => {}, ask: async () => "n" };
    await runApprove(fingerprint, io);
    const shown = outs.join("");
    assert.ok(shown.includes("location:  rev?exe.js:1"), `the location line was not sanitized:\n${shown}`);
    assert.ok(!shown.includes(RLO), "the bidi override reached the approval prompt");
  } finally {
    consent.setConsentRootForTests(undefined);
    rmSync(base, { recursive: true, force: true });
  }
});

// The approval prompt is the trust anchor, so these pin what it asks, what an
// affirmative answer records, and what a fingerprint echo shows. Each case uses
// its own consent root, so the real store is never touched.
function pendingApproval(file: string): { base: string; root: string; cred: string; fingerprint: string } {
  const base = mkdtempSync(path.join(tmpdir(), "sl-approve-pending-"));
  try {
    return buildPending(base, file);
  } catch (err) {
    // A failed setup must not leave the consent root pointing at a directory that is about to go.
    consent.setConsentRootForTests(undefined);
    rmSync(base, { recursive: true, force: true });
    throw err;
  }
}

function buildPending(base: string, file: string): { base: string; root: string; cred: string; fingerprint: string } {
  const root = path.join(base, "repo");
  mkdirSync(root);
  const cred = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";
  writeFileSync(path.join(root, file), `const t = "${cred}";\n`, "utf8");
  const config = loadConfig(root);
  const finding = scanText(readFileSync(path.join(root, file), "utf8"), { config, filePath: file }).find(
    (f) => f.ruleId === "github-token"
  );
  assert.ok(finding, "the fixture produced no github-token finding");
  const fingerprint = String(finding.fingerprint);
  consent.setConsentRootForTests(path.join(base, "store"));
  consent.writeRecord({
    version: consent.CONSENT_VERSION,
    id: consent.recordId(fingerprint, root),
    state: "pending",
    fingerprint,
    path: root,
    file,
    line: 1,
    ruleId: "github-token",
    provider: "GitHub",
    commitment: consent.commitmentOf(cred),
    createdAt: new Date().toISOString(),
  });
  return { base, root, cred, fingerprint };
}

test("an affirmative answer approves the record with the commitment of the raw credential", async () => {
  const fx = pendingApproval("app.js");
  try {
    const io: ApproveIO = { isTTY: true, out: () => {}, err: () => {}, ask: async () => "y" };
    assert.strictEqual(await runApprove(fx.fingerprint, io), 0);
    const after = consent.findByFingerprint(fx.fingerprint);
    assert.strictEqual(after.length, 1, "the record is not in the store after an affirmative answer");
    assert.strictEqual(after[0].state, "approved");
    assert.strictEqual(after[0].commitment, consent.commitmentOf(fx.cred), "the approval does not commit to the raw value");
  } finally {
    consent.setConsentRootForTests(undefined);
    rmSync(fx.base, { recursive: true, force: true });
  }
});

test("the consent question names the provider and keeps its exact wording", async () => {
  const fx = pendingApproval("app.js");
  try {
    const asked: string[] = [];
    const io: ApproveIO = {
      isTTY: true,
      out: () => {},
      err: () => {},
      ask: async (prompt) => {
        asked.push(prompt);
        return "n";
      },
    };
    await runApprove(fx.fingerprint, io);
    assert.deepStrictEqual(asked, ["Send this credential to GitHub? [y/N] "]);
  } finally {
    consent.setConsentRootForTests(undefined);
    rmSync(fx.base, { recursive: true, force: true });
  }
});

test("a fingerprint echoed back with a C1 control is printed sanitized", async () => {
  const base = mkdtempSync(path.join(tmpdir(), "sl-approve-fp-"));
  try {
    consent.setConsentRootForTests(path.join(base, "store"));
    const c1 = String.fromCharCode(0x9b);
    const errs: string[] = [];
    const io: ApproveIO = { isTTY: true, out: () => {}, err: (m) => errs.push(m), ask: async () => "n" };
    assert.strictEqual(await runApprove(`fp${c1}31m`, io), 2);
    const text = errs.join("");
    assert.ok(text.includes("no pending verification request for fp?31m."), `unexpected output: ${text}`);
    assert.ok(!text.includes(c1), "the C1 control was echoed to the terminal");
  } finally {
    consent.setConsentRootForTests(undefined);
    rmSync(base, { recursive: true, force: true });
  }
});

finish();
