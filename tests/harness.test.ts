import { test, suite, finish, assert } from "./harness";
import { mkdirSync, rmSync, writeFileSync } from "fs";
import { spawnSync } from "child_process";
import * as path from "path";

/**
 * The harness's contract is process-level — what it prints and what it exits
 * with — so it is checked by running real files through it rather than by
 * calling into it, which would be circular.
 */
const FIXTURE_DIR = path.join(__dirname, ".tmp-harness-fixtures");

interface Run {
  status: number | null;
  output: string;
}

function runFixture(body: string): Run {
  mkdirSync(FIXTURE_DIR, { recursive: true });
  const file = path.join(FIXTURE_DIR, `fixture-${Math.abs(hash(body))}.ts`);
  writeFileSync(
    file,
    `import { test, suite, finish, assert } from "../harness";\n${body}\nfinish();\n`,
    "utf8"
  );
  const res = spawnSync("npx", ["ts-node", "--transpile-only", file], {
    cwd: path.join(__dirname, ".."),
    encoding: "utf8",
    timeout: 60_000,
  });
  return { status: res.status, output: `${res.stdout ?? ""}${res.stderr ?? ""}` };
}

function hash(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0;
  return h;
}

suite("harness.ts — exit codes and reporting");

test("a passing sync test reports success and exits 0", () => {
  const run = runFixture(`test("passes", () => { assert.strictEqual(1, 1); });`);
  assert.strictEqual(run.status, 0);
  assert.match(run.output, /1 passed, 0 failed/);
});

test("a failing sync test is reported and exits non-zero", () => {
  const run = runFixture(`test("fails", () => { assert.strictEqual(1, 2, "nope"); });`);
  assert.notStrictEqual(run.status, 0);
  assert.match(run.output, /FAIL - fails/);
  assert.match(run.output, /0 passed, 1 failed/);
});

test("a rejecting async test is reported as failed, not as ok", () => {
  // It used to print "ok" and "1 passed, 0 failed", then crash on the unhandled
  // rejection. Non-zero, but the summary lied about which tests ran.
  const run = runFixture(
    `test("async fails", async () => { assert.strictEqual(1, 2, "async nope"); });`
  );
  assert.notStrictEqual(run.status, 0);
  assert.match(run.output, /FAIL - async fails/);
  assert.doesNotMatch(run.output, /ok - async fails/, "an awaited failure must not report ok");
  assert.match(run.output, /0 passed, 1 failed/);
});

test("an async test that never settles cannot report success", () => {
  // The silent one: the loop empties, node exits 0, and a green run means
  // nothing. This is what hid a hung verification test during fix #4.
  const run = runFixture(`test("hangs", async () => { await new Promise(() => {}); });`);
  assert.notStrictEqual(run.status, 0, "a file that never finishes must not exit 0");
});

test("a file that throws before reaching finish exits non-zero", () => {
  const run = runFixture(`test("never runs", () => {});\nthrow new Error("boom");`);
  assert.notStrictEqual(run.status, 0);
});

test("sync and async tests run in declaration order", () => {
  const run = runFixture(
    `suite("ordered");
     test("first", () => {});
     test("second", async () => { await Promise.resolve(); });
     test("third", () => {});`
  );
  assert.strictEqual(run.status, 0);
  const order = run.output.match(/ok - (first|second|third)/g);
  assert.deepStrictEqual(order, ["ok - first", "ok - second", "ok - third"]);
});

test("an async test is awaited before it is reported", () => {
  // The body logs after its await. If the harness does not await, "ok - slow"
  // is printed first and the marker arrives afterwards.
  const run = runFixture(
    `test("slow", async () => {
       await new Promise((r) => setTimeout(r, 50));
       console.log("  [body finished]");
     });`
  );
  assert.strictEqual(run.status, 0);
  assert.ok(
    run.output.indexOf("[body finished]") < run.output.indexOf("ok - slow"),
    "the test body must complete before the result is reported"
  );
});

test("fixture directory is cleaned up", () => {
  rmSync(FIXTURE_DIR, { recursive: true, force: true });
  assert.ok(true);
});

finish();
