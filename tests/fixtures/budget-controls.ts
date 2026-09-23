/*
 * DISPOSABLE diagnostic. Not a test, not product code. It always exits 0 and asserts nothing.
 *
 * Two jobs:
 *   1. PROVE the instrumentation is attached to the module that actually executes, by driving a
 *      known checkpoint to refuse and requiring the shim's expected event to appear in the log.
 *   2. Drive EACH exhaustion category deterministically, to establish which category a refusal
 *      belongs to, what the throw site knows, and what a user is finally told.
 *
 * Every exhaustion below is INJECTED. None of it reproduces the original unexplained 51 s delay
 * on test-windows (20), and nothing here should be read as doing so.
 */
import * as budget from "../../src/consent-budget";
import { consentStoreGuidance } from "../../src/consent";

const say = (s: string) => process.stderr.write("CONTROL " + s + "\n");

/** Runs one injected case inside a real budget and reports what the throw site carried. */
function run(label: string, fn: () => void): void {
  let outcome = "completed with no refusal";
  try {
    budget.withBudget(() => {
      fn();
      const s = budget.currentSpend();
      outcome =
        `no refusal; spend calls=${s?.helperCalls} bytes=${s?.helperBytes} ` +
        `entries=${s?.dirEntries} elapsedMs=${s?.elapsedMs}`;
    });
  } catch (e) {
    const err = e as Error & { what?: string };
    outcome = `REFUSED ${err.name} what=${String(err.what)}`;
  }
  say(`${label.padEnd(26)} -> ${outcome}`);
}

say(
  `LIMITS helperCalls=${budget.LIMITS.helperCalls} helperBytes=${budget.LIMITS.helperBytes} ` +
    `dirEntries=${budget.LIMITS.dirEntries} deadlineMs=${budget.LIMITS.deadlineMs}`,
);

/*
 * (1) ATTACHMENT CONTROL.
 * A clock pushed past the deadline MUST make checkBudgetDeadline refuse, and the shim MUST emit
 * "EXHAUSTED category=DEADLINE checkpoint=checkBudgetDeadline". If that BTRACE line is missing
 * from the captured log, the instrumentation is not attached to the executing module and no
 * other budget observation in this run may be relied on.
 */
say("ATTACHMENT CONTROL: expect a BTRACE EXHAUSTED category=DEADLINE checkpoint=checkBudgetDeadline line");
run("injected: deadline", () => {
  // withBudget has already captured startedAt from the REAL Date.now, so the fake clock has to
  // be anchored to real time and pushed past the deadline. An absolute small number would make
  // the elapsed time negative and refuse nothing.
  const past = Date.now() + budget.LIMITS.deadlineMs + 1;
  budget.setClockForTests(() => past);
  try {
    budget.checkBudgetDeadline();
  } finally {
    budget.setClockForTests(undefined);
  }
});

/* (2) One injected control per remaining category. */
run("injected: entry count", () => {
  for (let i = 0; i <= budget.LIMITS.dirEntries + 1; i += 1) budget.spendDirEntry();
});
run("injected: inspections", () => {
  for (let i = 0; i <= budget.LIMITS.helperCalls + 1; i += 1) budget.spendHelperCall();
});
run("injected: output bytes", () => {
  budget.spendHelperBytes(budget.LIMITS.helperBytes + 1);
});
run("injected: none (healthy)", () => {
  budget.spendDirEntry();
  budget.spendHelperCall();
  budget.spendHelperBytes(16);
});

/*
 * (3) What survives the translation to a user-visible answer. This is the §6 question: the throw
 * site above distinguishes four categories in BudgetExceededError.what; the sentence below is
 * what a person actually reads.
 */
say("");
say("WHAT THE USER IS TOLD, FOR EVERY ONE OF THE FOUR CATEGORIES:");
say(`  platform=${process.platform} problem code=operation-too-large (single code for all four)`);
for (const line of consentStoreGuidance("operation-too-large").split(/(?<=\. )/))
  say(`  | ${line.trim()}`);
