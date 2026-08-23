import { parseArgs, shouldFail, validateArgs, HELP } from "../src/cli";
import { Finding } from "../src/scanner";
import { test, suite, finish, assert } from "./harness";

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

suite("\ncli.ts — shouldFail");

test("shouldFail('verified') cannot fire on findings that were never verified", () => {
  // Documents why the guard above is necessary: shouldFail is not itself wrong.
  const findings = [finding(), finding()];
  assert.strictEqual(shouldFail(findings, "verified"), false);
  findings[0].verified = true;
  assert.strictEqual(shouldFail(findings, "verified"), true);
});

test("shouldFail('any') fires on any finding at all", () => {
  assert.strictEqual(shouldFail([finding({ severity: "low" })], "any"), true);
  assert.strictEqual(shouldFail([], "any"), false);
});

test("shouldFail('high') covers critical as well as high", () => {
  assert.strictEqual(shouldFail([finding({ severity: "critical" })], "high"), true);
  assert.strictEqual(shouldFail([finding({ severity: "high" })], "high"), true);
  assert.strictEqual(shouldFail([finding({ severity: "medium" })], "high"), false);
});

test("shouldFail('never') never fires", () => {
  assert.strictEqual(shouldFail([finding({ verified: true })], "never"), false);
});

finish();
