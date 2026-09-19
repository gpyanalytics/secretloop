/**
 * AN AGGREGATE WORK BUDGET FOR ONE CONSENT OPERATION.
 *
 * Why this exists. Each check on its own is bounded — a subprocess has a timeout and an output
 * cap, the ancestor walk has a component cap — but nothing bounded the SUM. Measured on macOS with
 * a real `/bin/ls` per inspected object:
 *
 *            operation          shallow chain      deep temp chain
 *            readRecord                 7 calls          16 calls
 *            writeRecord               16                43
 *            approveRecord             24                60
 *            listRecords, 1 record     13                31
 *            listRecords, 50 records   62                80
 *
 * Two things stand out. Work repeats within a single operation — `writeRecord` made 43 calls about
 * 10 distinct objects, because `ensureDir` and the write each re-walk the chain — and `listRecords`
 * grows with the record count with no ceiling at all. Per-subprocess timeouts do not bound either:
 * 512 helpers that each take their full timeout is not a bounded operation.
 *
 * WHAT THIS DOES AND DOES NOT GUARANTEE.
 *
 *   - The work limits are hard. Once a counter is exhausted no further work is started, and the
 *     operation refuses.
 *   - The deadline is checked BETWEEN units of work. It is not a wall-clock guarantee, because a
 *     synchronous `lstat`, `readdir` or `open` on an unresponsive mount cannot be interrupted from
 *     inside this process. A child process IS bounded: it gets only the time remaining, and is
 *     killed outright when that runs out.
 *   - Nothing is cached. The budget exists so repeated work can be PAID FOR and capped, not so it
 *     can be skipped: a remembered "safe" answer would keep asserting something about a directory
 *     that may since have changed, which is the property these checks exist to provide.
 *
 * Scope: consent-store work only. Provider request timeouts and the atomic claim before
 * transmission are untouched.
 */

/** Thrown when an operation exceeds its allowance. Translated by consent.ts; never surfaced raw. */
export class BudgetExceededError extends Error {
  constructor(public readonly what: string) {
    super("consent operation budget exhausted: " + what);
    this.name = "BudgetExceededError";
  }
}

/**
 * The limits, and why each is what it is. Every one is grounded in the table above and then given
 * room, because the measurements come from one arm64 laptop and a supported runner may be slower
 * and a real store larger. A worst case is not inferred from an average.
 */
export const LIMITS = {
  /**
   * Helper invocations. The heaviest legitimate case measured was 80 (deep chain, 50 records);
   * 512 is about six times that, and leaves room for a deeper home and several hundred records.
   */
  helperCalls: 512,
  /**
   * Aggregate helper output. Each response is already capped at 64 KiB, so this bounds the total
   * rather than re-bounding one response: 512 responses at 8 KiB, or 64 at the full cap.
   */
  helperBytes: 4 * 1024 * 1024,
  /**
   * Directory entries considered in `pending`. Enumeration itself is bounded, not filtered after
   * the fact: the directory is read through an iterator and stops at this many. Consent records
   * are short-lived, so a store holding more than this is not a store in normal use.
   */
  dirEntries: 256,
  /**
   * Total elapsed for one operation. The heaviest legitimate case measured 110 ms, so this is
   * well over a hundred times that; it is not a latency target but a ceiling, and it is what
   * stops 512 helpers each taking their own timeout from adding up to forty minutes.
   */
  deadlineMs: 20_000,
} as const;

interface Budget {
  helperCalls: number;
  helperBytes: number;
  dirEntries: number;
  startedAt: number;
}

let active: Budget | undefined;

/**
 * The clock, swappable for tests only. A deadline case driven by real sleeping is either slow or
 * flaky; a controlled clock makes it deterministic, and the record labels those cases as
 * simulated and pairs them with native measurements.
 */
let now: () => number = Date.now;

export function setClockForTests(fn: (() => number) | undefined): void {
  now = fn ?? Date.now;
}

/**
 * Run `fn` under a budget. A NESTED call joins the budget already running rather than starting a
 * fresh one — `approveRecord` calls `readRecord` and `writeRecord`, and three full allowances for
 * one user-visible operation would be no allowance at all.
 */
export function withBudget<T>(fn: () => T): T {
  if (active) return fn();
  active = { helperCalls: 0, helperBytes: 0, dirEntries: 0, startedAt: now() };
  try {
    return fn();
  } finally {
    active = undefined;
  }
}

/** Test seam: how much of the current allowance has been spent. Undefined when none is active. */
export function currentSpend(): { helperCalls: number; helperBytes: number; dirEntries: number; elapsedMs: number } | undefined {
  return active && {
    helperCalls: active.helperCalls,
    helperBytes: active.helperBytes,
    dirEntries: active.dirEntries,
    elapsedMs: now() - active.startedAt,
  };
}

function checkDeadline(): void {
  if (!active) return;
  if (now() - active.startedAt >= LIMITS.deadlineMs) {
    throw new BudgetExceededError("time");
  }
}

/**
 * Milliseconds left, for handing to a child so it cannot outlive the operation. Returns `cap`
 * when no budget is active, which is only the case outside a consent entry point.
 */
export function remainingMs(cap: number): number {
  if (!active) return cap;
  const left = LIMITS.deadlineMs - (now() - active.startedAt);
  if (left <= 0) throw new BudgetExceededError("time");
  return Math.max(1, Math.min(cap, left));
}

/** Charge one helper invocation BEFORE starting it, so the cap stops work rather than reporting it. */
export function spendHelperCall(): void {
  checkDeadline();
  if (!active) return;
  if (active.helperCalls + 1 > LIMITS.helperCalls) throw new BudgetExceededError("inspections");
  active.helperCalls += 1;
}

/** Charge a helper's output once it is in hand. */
export function spendHelperBytes(bytes: number): void {
  if (!active) return;
  if (active.helperBytes + bytes > LIMITS.helperBytes) throw new BudgetExceededError("output");
  active.helperBytes += bytes;
}

/**
 * Charge one directory entry as it is read. Called from inside the enumeration loop, so a
 * directory larger than the allowance is never fully loaded: the read stops instead.
 */
export function spendDirEntry(): void {
  checkDeadline();
  if (!active) return;
  if (active.dirEntries + 1 > LIMITS.dirEntries) throw new BudgetExceededError("records");
  active.dirEntries += 1;
}

/** Charge nothing; just refuse if the clock has run out. For loops that do no helper work. */
export function checkBudgetDeadline(): void {
  checkDeadline();
}
