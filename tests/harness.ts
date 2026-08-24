import * as assert from "node:assert";

/**
 * The shared test harness.
 *
 * `test` used to take `() => void` and call it without awaiting, which made an
 * async body report "ok" before it had done anything. A rejecting one then
 * printed a summary that lied about which tests ran; a *hanging* one emptied the
 * event loop and exited 0, so a green run meant nothing. That is how a hung
 * verification test slipped through during the timeout work.
 *
 * Four test files grew their own awaiting harness to work around it, each with
 * its own copy of the fail-closed exit code — and the shared one had none, which
 * is drift that only widens. So tests are queued here and run by `finish`,
 * which awaits each one. Every call site keeps the same three-function shape.
 */
type TestFn = () => void | Promise<void>;

type Entry = { kind: "suite"; name: string } | { kind: "test"; name: string; fn: TestFn };

const queue: Entry[] = [];
let passed = 0;
let failed = 0;

export function suite(name: string): void {
  queue.push({ kind: "suite", name });
}

export function test(name: string, fn: TestFn): void {
  queue.push({ kind: "test", name, fn });
}

/**
 * Runs everything queued so far.
 *
 * Sets a failing exit code first and clears it only once the summary has
 * printed, so a file that never reaches the end cannot report success. A test
 * that never settles leaves the loop empty, node exits — and the code is still
 * non-zero, because nothing cleared it.
 */
export function finish(): void {
  process.exitCode = 1;
  void run();
}

async function run(): Promise<void> {
  for (const entry of queue) {
    if (entry.kind === "suite") {
      console.log(entry.name);
      continue;
    }
    try {
      await entry.fn();
      passed++;
      console.log(`  ok - ${entry.name}`);
    } catch (err: any) {
      failed++;
      console.log(`  FAIL - ${entry.name}`);
      console.log(`    ${err.message}`);
    }
  }

  console.log(`\n${passed} passed, ${failed} failed\n`);
  process.exitCode = failed > 0 ? 1 : 0;
}

export { assert };
