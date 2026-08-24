import {
  applyBaseline,
  mergeBaseline,
  parseArgs,
  evaluateGate,
  triageFindings,
  validateArgs,
  HELP,
} from "../src/cli";
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

finish();
