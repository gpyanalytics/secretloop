import { test, suite, finish, assert } from "./harness";
import * as budget from "../src/consent-budget";
import * as acl from "../src/consent-acl-win";
import type { SpawnSyncReturns } from "child_process";

/**
 * THE WINDOWS HELPERS AGAINST THE OPERATION ALLOWANCE.
 *
 * Every one of these failed against main, where `src/consent-acl-win.ts` imported nothing from
 * the budget: `spendHelperCall`, `spendHelperBytes`, `remainingMs` and `remainingBytes` each
 * appeared zero times in it. Three PowerShell inspections ran with `remainingCalls=512` untouched
 * afterwards, and each child was handed a fixed 60,000 ms timeout while its operation had about
 * 18,800 ms left -- measured in the packaged server, not inferred.
 *
 * WHAT THESE CASES ARE. They drive the real accounting through a SPAWN SEAM that replaces the
 * child process, so they run on every platform and are exact. They do not measure any real
 * PowerShell, and they are not evidence that a real helper takes any particular time. The
 * DEADLINE cases additionally use a CONTROLLED CLOCK and are SIMULATED in the same sense the
 * existing budget suite means it: they show the allowance refuses when the clock says the time
 * has gone, not that a real operation ever takes that long. Native behaviour is measured
 * separately on Windows runners and recorded there.
 */

suite("windows consent helpers charge against the operation allowance");

/**
 * `inspectPaths` and `protectDirectory` both resolve their executables through the tools seam,
 * so they can be driven anywhere. `currentUserSid` resolves whoami.exe from SystemRoot directly
 * and returns before charging on a non-Windows host; it takes the same code path as these two
 * and is covered by the native Windows evidence rather than by widening a seam for a test.
 */
const SOME_PATH = "C:\\Users\\someone\\.secretloop";
const SOME_SID = "S-1-5-21-1-1-1-1003";

/** A child that never ran: what the seam returns when a test does not care about the output. */
function reply(stdout = "", stderr = "", status: number | null = 0): SpawnSyncReturns<string> {
  return {
    pid: 0, output: [null, stdout, stderr], stdout, stderr,
    status, signal: null, error: undefined,
  } as SpawnSyncReturns<string>;
}

/** Records what each spawn was ASKED for, which is where the propagated bounds show up. */
function recorder(respond: () => SpawnSyncReturns<string> = () => reply()) {
  const calls: acl.HelperSpawn[] = [];
  acl.setHelperRunnerForTests((c) => { calls.push(c); return respond(); });
  return calls;
}

function reset(): void {
  acl.setHelperRunnerForTests(undefined);
  acl.setWindowsAclToolsForTests(undefined);
  budget.setClockForTests(undefined);
}

/** whoami and icacls are resolved through the tools override so no real path is touched. */
function fakeTools(): void {
  acl.setWindowsAclToolsForTests({
    powershell: __filename, icacls: __filename, whoami: __filename,
  } as never);
}

// ---------------------------------------------------------------------------------------------
// invocation counting
// ---------------------------------------------------------------------------------------------

test("a Windows helper invocation is charged, so the inspection cap is reachable at all", () => {
  reset(); fakeTools();
  const calls = recorder(() => reply('{}'));
  try {
    budget.withBudget(() => {
      acl.inspectPaths([SOME_PATH]);
      const spent = budget.currentSpend();
      assert.strictEqual(spent?.helperCalls, 1, "the inspection charged nothing");
    });
  } finally { reset(); }
  assert.strictEqual(calls.length, 1);
});

test("helper-count exhaustion refuses, and refuses BEFORE the child is spawned", () => {
  reset(); fakeTools();
  const calls = recorder(() => reply('{}'));
  let refused: budget.BudgetExceededError | undefined;
  try {
    budget.withBudget(() => {
      for (let i = 0; i < budget.LIMITS.helperCalls; i++) budget.spendHelperCall();
      try { acl.inspectPaths([SOME_PATH]); } catch (e) { refused = e as budget.BudgetExceededError; }
    });
  } finally { reset(); }
  assert.strictEqual(refused?.name, "BudgetExceededError");
  assert.strictEqual(refused?.what, "inspections");
  assert.strictEqual(calls.length, 0, "the allowance was exhausted and a child still started");
});

test("a helper attempt that fails to start is still charged", () => {
  reset(); fakeTools();
  acl.setHelperRunnerForTests(() => { throw new Error("spawn EPERM"); });
  try {
    budget.withBudget(() => {
      const verdict = acl.inspectPaths([SOME_PATH]);
      assert.strictEqual(verdict.ok, false, "a child that could not start is not a verdict");
      assert.strictEqual(budget.currentSpend()?.helperCalls, 1, "a failed attempt cost nothing");
    });
  } finally { reset(); }
});

// ---------------------------------------------------------------------------------------------
// remaining time
// ---------------------------------------------------------------------------------------------

test("the child is given what is LEFT of the operation, not a fresh fixed timeout", () => {
  reset(); fakeTools();
  const calls = recorder(() => reply('{}'));
  try {
    const t0 = 1_000_000;
    let reads = 0;
    // SIMULATED CLOCK: the first read starts the operation, every later read is 19.5 s on.
    budget.setClockForTests(() => (reads++ === 0 ? t0 : t0 + 19_500));
    budget.withBudget(() => acl.inspectPaths([SOME_PATH]));
  } finally { reset(); }
  assert.strictEqual(calls.length, 1);
  assert.strictEqual(calls[0].timeout, 500, "the child outlived the operation's remaining time");
});

test("the per-helper ceiling still applies when the operation has more time than it", () => {
  reset(); fakeTools();
  const calls = recorder(() => reply('{}'));
  try { budget.withBudget(() => acl.inspectPaths([SOME_PATH])); } finally { reset(); }
  // 60,000 is HELPER_TIMEOUT_MS; the allowance is 20,000, so the smaller one binds. The point
  // is that a bound is chosen rather than a fixed ceiling being passed through.
  assert.ok(calls[0].timeout <= 20_000, `timeout ${calls[0].timeout} exceeds the whole allowance`);
  assert.ok(calls[0].timeout > 0, "a zero timeout would mean NO timeout at all");
});

test("an expired deadline refuses before the spawn and never passes timeout 0", () => {
  reset(); fakeTools();
  const calls = recorder(() => reply('{}'));
  let refused: budget.BudgetExceededError | undefined;
  try {
    const t0 = 1_000_000;
    let reads = 0;
    budget.setClockForTests(() => (reads++ === 0 ? t0 : t0 + budget.LIMITS.deadlineMs + 1));
    budget.withBudget(() => {
      try { acl.inspectPaths([SOME_PATH]); } catch (e) { refused = e as budget.BudgetExceededError; }
    });
  } finally { reset(); }
  assert.strictEqual(refused?.name, "BudgetExceededError");
  assert.strictEqual(refused?.what, "time");
  assert.strictEqual(calls.length, 0, "a child started after the deadline had passed");
});

test("expiry DURING the helper is caught at the post-helper boundary", () => {
  reset(); fakeTools();
  let refused: budget.BudgetExceededError | undefined;
  try {
    const t0 = 1_000_000;
    let reads = 0;
    // Reads: 0 starts the operation, 1 is spendHelperCall's own check, 2 is remainingMs before
    // the spawn -- all inside the allowance. From read 3 the time is gone, which is the
    // post-helper check.
    budget.setClockForTests(() => (reads++ < 3 ? t0 : t0 + budget.LIMITS.deadlineMs + 1));
    acl.setHelperRunnerForTests(() => reply('{}'));
    budget.withBudget(() => {
      try { acl.inspectPaths([SOME_PATH]); } catch (e) { refused = e as budget.BudgetExceededError; }
    });
  } finally { reset(); }
  assert.strictEqual(refused?.what, "time", "the helper ran the clock out and nothing noticed");
});

// ---------------------------------------------------------------------------------------------
// output
// ---------------------------------------------------------------------------------------------

test("captured output is charged, and stderr counts because maxBuffer counts it", () => {
  reset(); fakeTools();
  acl.setHelperRunnerForTests(() => reply("x".repeat(100), "y".repeat(50)));
  try {
    budget.withBudget(() => {
      acl.inspectPaths([SOME_PATH]);
      assert.strictEqual(budget.currentSpend()?.helperBytes, 150, "stdout+stderr not charged");
    });
  } finally { reset(); }
});

test("output from a FAILED helper is charged too", () => {
  reset(); fakeTools();
  acl.setHelperRunnerForTests(() => reply("noise".repeat(10), "", 1));
  try {
    budget.withBudget(() => {
      assert.strictEqual(acl.inspectPaths([SOME_PATH]).ok, false, "a non-zero exit is not a verdict");
      assert.strictEqual(budget.currentSpend()?.helperBytes, 50, "a failing helper ran free");
    });
  } finally { reset(); }
});

test("the child's buffer is bounded by what the operation has left, not only its own cap", () => {
  reset(); fakeTools();
  const calls = recorder(() => reply('{}'));
  try {
    budget.withBudget(() => {
      budget.spendHelperBytes(budget.LIMITS.helperBytes - 1024);
      acl.inspectPaths([SOME_PATH]);
    });
  } finally { reset(); }
  assert.strictEqual(calls[0].maxBuffer, 1024, "the child could buffer past the whole allowance");
  assert.ok(calls[0].maxBuffer > 0, "a zero maxBuffer would mean UNLIMITED");
});

test("an exhausted output allowance refuses before the spawn", () => {
  reset(); fakeTools();
  const calls = recorder(() => reply('{}'));
  let refused: budget.BudgetExceededError | undefined;
  try {
    budget.withBudget(() => {
      budget.spendHelperBytes(budget.LIMITS.helperBytes);
      try { acl.inspectPaths([SOME_PATH]); } catch (e) { refused = e as budget.BudgetExceededError; }
    });
  } finally { reset(); }
  assert.strictEqual(refused?.what, "output");
  assert.strictEqual(calls.length, 0);
});

// ---------------------------------------------------------------------------------------------
// classification through the catch paths
// ---------------------------------------------------------------------------------------------

test("a budget refusal inside inspectPaths is NOT relabelled as an ACL tooling problem", () => {
  reset(); fakeTools();
  let refused: unknown;
  try {
    budget.withBudget(() => {
      for (let i = 0; i < budget.LIMITS.helperCalls; i++) budget.spendHelperCall();
      try { acl.inspectPaths([SOME_PATH]); } catch (e) { refused = e; }
    });
  } finally { reset(); }
  assert.ok(refused instanceof budget.BudgetExceededError, "exhaustion became an ACL verdict");
  assert.strictEqual((refused as budget.BudgetExceededError).what, "inspections");
});

test("a budget refusal inside protectDirectory is NOT relabelled as enforcement failure", () => {
  reset(); fakeTools();
  let refused: unknown;
  try {
    budget.withBudget(() => {
      budget.spendHelperBytes(budget.LIMITS.helperBytes);
      try { acl.protectDirectory(SOME_PATH, SOME_SID); } catch (e) { refused = e; }
    });
  } finally { reset(); }
  assert.ok(refused instanceof budget.BudgetExceededError, "exhaustion became an ACL verdict");
  assert.strictEqual((refused as budget.BudgetExceededError).what, "output");
});

// ---------------------------------------------------------------------------------------------
// the shape of the allowance itself
// ---------------------------------------------------------------------------------------------

test("nested consent calls share ONE allowance rather than each getting a fresh one", () => {
  reset(); fakeTools();
  recorder(() => reply('{}'));
  try {
    budget.withBudget(() => {
      acl.inspectPaths([SOME_PATH]);
      budget.withBudget(() => acl.inspectPaths([SOME_PATH]));
      assert.strictEqual(budget.currentSpend()?.helperCalls, 2, "the nested call reset the books");
    });
  } finally { reset(); }
});

test("the allowance is released after success, and after an exception", () => {
  reset(); fakeTools();
  recorder(() => reply('{}'));
  try {
    budget.withBudget(() => acl.inspectPaths([SOME_PATH]));
    assert.strictEqual(budget.currentSpend(), undefined, "state survived a successful operation");
    acl.setHelperRunnerForTests(() => { throw new budget.BudgetExceededError("time"); });
    try { budget.withBudget(() => acl.inspectPaths([SOME_PATH])); } catch { /* expected */ }
    assert.strictEqual(budget.currentSpend(), undefined, "state survived an exception");
  } finally { reset(); }
});

finish();
