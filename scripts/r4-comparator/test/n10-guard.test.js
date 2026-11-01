"use strict";
// Run with: npm run test:comparator. Adversarial controls for the checks that the three historical N10
// cases really ran. Each control keeps those cases from running in a way an exit code alone would not
// show, and expects a failure. None needs the N10 record: a case that does not run fails the checks
// whether or not the record exists. The last section controls the runner's per-file time limit and
// its cleanup. Children write only under R4_TEST_TMP if set, else a fresh directory under the system
// temp directory.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync, spawn: spawnAsync } = require("child_process");

const MAIN = path.join(__dirname, "compare-fail-closed.test.js");
const RUNNER = path.join(__dirname, "run-comparator-tests.js");
const SCRATCH = process.env.R4_TEST_TMP || fs.mkdtempSync(path.join(os.tmpdir(), "r4-guard-tests-"));
const MISSING_ROOT = path.join(SCRATCH, "no-n10-record-here");
const N10_IDS = ["n10-reproduction", "n10-without-reproduction", "n10-tamper-refused"];
const N10_NAMES = [
  "N10 reproduction: PASS-REPRODUCTION, 27 recorded differences, zero finding-level differences, frozen evidence unchanged",
  "N10 without the reproduction is FAIL, with 27 unapproved metadata differences",
  "N10 reproduction refuses a changed finding in a scratch copy: the pinned bytes no longer match",
];
const NOT_RUN = /these historical N10 cases did not run to completion: n10-reproduction, n10-without-reproduction, n10-tamper-refused/;

function scratch(name) {
  fs.mkdirSync(SCRATCH, { recursive: true });
  return fs.mkdtempSync(path.join(SCRATCH, `${name}-`));
}

// A child's environment: no enclosing test-runner context and no N10 or time-limit settings beyond
// those given.
function childEnv(extra) {
  const env = { ...process.env };
  for (const key of ["NODE_TEST_CONTEXT", "NODE_OPTIONS", "R4_N10_ROOT", "R4_REQUIRE_N10", "R4_N10_RECEIPT", "R4_RUNNER_TIMEOUT_MS"]) {
    delete env[key];
  }
  return { ...env, R4_TEST_TMP: SCRATCH, ...extra };
}

const spawn = (args, extra) => spawnSync(process.execPath, args, { env: childEnv(extra), encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
const direct = (extra) => spawn(["--test", "--test-reporter=tap", MAIN], extra);
const output = (r) => `${r.stdout}\n${r.stderr}`;

// Whether this Node accepts the option in NODE_OPTIONS. Node 18 and 20 refuse the name and skip
// patterns there, so on those versions that filter cannot be applied at all.
const accepts = (flag) => process.allowedNodeEnvironmentFlags.has(flag);

// An N10 case that ran reports "ok N - N10 ..." with no SKIP directive; the names hold no "#".
const N10_RAN = /^ok \d+ - N10 [^#]*$/m;

// ---------------------------------------------------------------- direct runs: the completion check

const FILTERS = [
  ["--test-name-pattern", "--test-name-pattern=^D4"],
  ["--test-skip-pattern", "--test-skip-pattern=N10"],
  ["--test-only", "--test-only"],
];

for (const [flag, option] of FILTERS) {
  test(`direct run: ${flag} in NODE_OPTIONS cannot pass a run under R4_REQUIRE_N10=1 in which the N10 cases did not run`, (t) => {
    const guarded = direct({ NODE_OPTIONS: option, R4_REQUIRE_N10: "1", R4_N10_ROOT: MISSING_ROOT });
    if (!accepts(flag)) {
      assert.equal(guarded.status, 9, output(guarded));
      assert.match(output(guarded), /not allowed in NODE_OPTIONS/);
      t.diagnostic(`Node ${process.version} refuses ${flag} in NODE_OPTIONS, so the filter cannot be applied`);
      return;
    }
    // Control: without the requirement the same filter exits 0 and no N10 case runs. This is the bypass.
    const control = direct({ NODE_OPTIONS: option, R4_N10_ROOT: MISSING_ROOT });
    assert.equal(control.status, 0, output(control));
    assert.doesNotMatch(control.stdout, N10_RAN);
    assert.notEqual(guarded.status, 0, output(guarded));
    assert.match(output(guarded), NOT_RUN);
  });
}

test("direct run: any R4_REQUIRE_N10 value arms the completion check, the empty string included", () => {
  for (const value of ["1", "", "0", "true"]) {
    const r = direct({ NODE_OPTIONS: "--test-only", R4_REQUIRE_N10: value, R4_N10_ROOT: MISSING_ROOT });
    assert.notEqual(r.status, 0, `R4_REQUIRE_N10=${JSON.stringify(value)}\n${output(r)}`);
    assert.match(output(r), NOT_RUN);
  }
});

// ---------------------------------------------------------------- the runner

test("runner: a set NODE_OPTIONS fails both modes before any test runs", (t) => {
  const options = ["--max-old-space-size=512"];
  if (accepts("--test-shard")) {
    options.push("--test-shard=2/3");
    // Control: a shard that leaves the file out passes a direct run with no results, even under
    // R4_REQUIRE_N10=1, because the file never loads. Only the runner's refusal stops it.
    const shard = direct({ NODE_OPTIONS: "--test-shard=2/3", R4_REQUIRE_N10: "1", R4_N10_ROOT: MISSING_ROOT });
    assert.equal(shard.status, 0, output(shard));
    assert.doesNotMatch(shard.stdout, /^(not )?ok \d+ - /m);
  } else {
    t.diagnostic(`Node ${process.version} refuses --test-shard in NODE_OPTIONS`);
  }
  for (const option of options) {
    for (const args of [[RUNNER], [RUNNER, "--require-n10"]]) {
      const r = spawn(args, { NODE_OPTIONS: option, R4_N10_ROOT: MISSING_ROOT });
      assert.equal(r.status, 1, `${option} ${args.slice(1).join(" ")}\n${output(r)}`);
      assert.match(r.stdout, /: FAIL\n {2}problem: NODE_OPTIONS is set/);
      assert.doesNotMatch(r.stdout, /^# tests /m, "a test ran although NODE_OPTIONS was set");
    }
  }
});

test("runner: usage errors exit 64", () => {
  assert.equal(spawn([RUNNER, "--require-n11"], {}).status, 64);
  assert.equal(spawn([RUNNER, "--require-n10", "x"], {}).status, 64);
});

// A copy of the runner beside stub test files, so its checks run against reports chosen here. Each case
// is { name, skip, receipt }: a skip reason, and the ids the case appends to the receipt when it runs.
function stubRunner(mainCases, guardCases = [{ name: "stub guard" }]) {
  const dir = scratch("stub-runner");
  const source = (cases) =>
    'const { test } = require("node:test");\nconst fs = require("fs");\n' +
    cases
      .map((c) => {
        const opts = c.skip ? `{ skip: ${JSON.stringify(c.skip)} }, ` : "";
        const body = (c.receipt || []).map((id) => `fs.appendFileSync(process.env.R4_N10_RECEIPT, ${JSON.stringify(`${id}\n`)});`).join(" ");
        return `test(${JSON.stringify(c.name)}, ${opts}() => { ${body} });\n`;
      })
      .join("");
  fs.copyFileSync(RUNNER, path.join(dir, "run-comparator-tests.js"));
  fs.writeFileSync(path.join(dir, "compare-fail-closed.test.js"), source(mainCases));
  fs.writeFileSync(path.join(dir, "n10-guard.test.js"), source(guardCases));
  return (...args) => spawn([path.join(dir, "run-comparator-tests.js"), ...args], {});
}

const n10Cases = (receipts) => N10_NAMES.map((name, i) => ({ name, receipt: receipts[i] }));

test("runner --require-n10: three passing N10 cases with a complete receipt PASS (control)", () => {
  const r = stubRunner(n10Cases(N10_IDS.map((id) => [id])))("--require-n10");
  assert.equal(r.status, 0, output(r));
  assert.match(r.stdout, /\): PASS\n/);
});

test("runner --require-n10: passing N10 cases that leave no receipt FAIL, though the test run exits 0", () => {
  const r = stubRunner(n10Cases([[], [], []]))("--require-n10");
  assert.equal(r.status, 1, output(r));
  assert.match(r.stdout, /# fail 0/);
  assert.match(r.stdout, /the N10 receipt holds \[\], not exactly/);
});

test("runner --require-n10: a receipt missing one id, or repeating one, FAILs", () => {
  for (const receipts of [[["n10-reproduction"], ["n10-without-reproduction"], []], [["n10-reproduction"], ["n10-reproduction"], ["n10-tamper-refused"]]]) {
    const r = stubRunner(n10Cases(receipts))("--require-n10");
    assert.equal(r.status, 1, output(r));
    assert.match(r.stdout, /the N10 receipt holds .*did not all run to completion/);
  }
});

test("runner --require-n10: a skipped N10 case FAILs even when the receipt is complete", () => {
  const cases = n10Cases([N10_IDS, [], []]);
  cases[2].skip = "historical N10 case not run";
  const r = stubRunner(cases)("--require-n10");
  assert.equal(r.status, 1, output(r));
  assert.match(r.stdout, /skip not allowed: N10 reproduction refuses/);
});

test("runner: a routine run allows the three N10 skips and refuses any other skip", () => {
  const n10Skips = N10_NAMES.map((name) => ({ name, skip: "historical N10 case not run" }));
  const ok = stubRunner([{ name: "a mandatory control" }, ...n10Skips])();
  assert.equal(ok.status, 0, output(ok));
  assert.match(ok.stdout, /compare-fail-closed\.test\.js: 4 tests, 1 passed, 3 skipped/);
  const bad = stubRunner([{ name: "a mandatory control", skip: "not today" }, ...n10Skips])();
  assert.equal(bad.status, 1, output(bad));
  assert.match(bad.stdout, /skip not allowed: a mandatory control \(not today\)/);
  const guardSkip = stubRunner([{ name: "a mandatory control" }], [{ name: "a guard control", skip: "x" }])();
  assert.equal(guardSkip.status, 1, output(guardSkip));
  assert.match(guardSkip.stdout, /n10-guard\.test\.js: skip not allowed: a guard control/);
});

test("runner: a file that reports no results FAILs", () => {
  const r = stubRunner([])();
  assert.equal(r.status, 1, output(r));
  assert.match(r.stdout, /compare-fail-closed\.test\.js: no test results were reported/);
});

// ---------------------------------------------------------------- the runner's time limit and cleanup

// Every stub runner below is bounded twice: by R4_RUNNER_TIMEOUT_MS inside it, and by a watchdog here
// that SIGKILLs it, so no control can hold a CI job open.
const WATCHDOG_MS = 60 * 1000;
const POSIX = process.platform !== "win32";
// The runner allowlists this name as a skip on Windows; keep the two spellings identical.
const SIGNAL_CONTROL_NAME = "runner: SIGHUP, SIGINT and SIGTERM each fail the run and kill the running file's processes";
const PASSING_FILE = 'const { test } = require("node:test");\ntest("a", () => {});\n';
const LIMIT_REFUSED = /problem: R4_RUNNER_TIMEOUT_MS must be a whole number of milliseconds from 1000 to 3600000/;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// A test file whose one test starts a grandchild, records "<grandchild> <test file> <node --test>"
// pids in pidFile, and never settles.
const hangingFile = (pidFile) => `const { test } = require("node:test");
const { spawn } = require("child_process");
const fs = require("fs");
test("never settles", () => new Promise(() => {
  const grandchild = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: "ignore" });
  fs.writeFileSync(${JSON.stringify(pidFile)}, [grandchild.pid, process.pid, process.ppid].join(" "));
  setInterval(() => {}, 1000);
}));
`;

// A copy of the runner beside the given main file and a passing guard file. Returns the copy's path.
function rawStubRunner(mainSource) {
  const dir = scratch("limit-runner");
  fs.copyFileSync(RUNNER, path.join(dir, "run-comparator-tests.js"));
  fs.writeFileSync(path.join(dir, "compare-fail-closed.test.js"), mainSource);
  fs.writeFileSync(path.join(dir, "n10-guard.test.js"), PASSING_FILE);
  return path.join(dir, "run-comparator-tests.js");
}

const watched = (runner, extra) =>
  spawnSync(process.execPath, [runner], { env: childEnv(extra), encoding: "utf8", maxBuffer: 64 * 1024 * 1024, timeout: WATCHDOG_MS, killSignal: "SIGKILL" });

const alive = (pid) => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err.code === "EPERM";
  }
};

// The three pids the hanging file recorded, waiting up to 15 s for it to record them.
async function recordedPids(pidFile) {
  for (const end = Date.now() + 15000; Date.now() < end; await sleep(50)) {
    let fields = [];
    try {
      fields = fs.readFileSync(pidFile, "utf8").trim().split(" ");
    } catch {
      // Not written yet.
    }
    if (fields.length === 3) return fields.map(Number);
  }
  throw new Error(`the hanging file never recorded its pids in ${pidFile}`);
}

// The pids still alive after up to 3 s. Survivors are then killed, so a failing control cannot leave
// processes behind either.
async function survivors(pids) {
  for (const end = Date.now() + 3000; Date.now() < end && pids.some(alive); ) await sleep(50);
  const left = pids.filter(alive);
  for (const pid of left) {
    try {
      process.kill(pid, "SIGKILL");
    } catch {
      // Already gone.
    }
  }
  return left;
}

test("runner: a never-settling file fails at the R4_RUNNER_TIMEOUT_MS limit, and none of its processes survive", async (t) => {
  const pidFile = path.join(scratch("pids"), "pids");
  const started = Date.now();
  const r = watched(rawStubRunner(hangingFile(pidFile)), { R4_RUNNER_TIMEOUT_MS: "3000" });
  const ms = Date.now() - started;
  const pids = await recordedPids(pidFile);
  const left = await survivors(pids);
  assert.equal(r.status, 1, output(r));
  assert.match(r.stdout, /, limit 3 s per file\): FAIL\n/);
  assert.match(r.stdout, /problem: compare-fail-closed\.test\.js: timed out after 3 s; node --test and the processes it started were killed/);
  assert.ok(ms < WATCHDOG_MS / 2, `the runner took ${ms} ms to stop a file with a 3 s limit`);
  if (POSIX) assert.deepEqual(left, [], `processes of the timed-out file survived: ${left.join(", ")}`);
  else t.diagnostic(`Windows: survivors after taskkill [${left.join(", ")}] are recorded, not asserted; native cleanup is unverified here`);
});

test("runner: a file that completes within the limit passes, and the summary shows the limit in force", () => {
  const r = watched(rawStubRunner(PASSING_FILE), { R4_RUNNER_TIMEOUT_MS: "3600000" });
  assert.equal(r.status, 0, output(r));
  assert.match(r.stdout, /\(routine, limit 3600 s per file\): PASS\n/);
});

test("runner: without R4_RUNNER_TIMEOUT_MS the limit is the finite default of 300 s", () => {
  const r = watched(rawStubRunner(PASSING_FILE), {});
  assert.equal(r.status, 0, output(r));
  assert.match(r.stdout, /\(routine, limit 300 s per file\): PASS\n/);
});

test("runner: an R4_RUNNER_TIMEOUT_MS that is not a whole number of ms from 1000 to 3600000 fails before any test runs", () => {
  const runner = rawStubRunner(PASSING_FILE);
  for (const value of ["", "0", "999", "3600001", "-1", "abc", "1e4", " 5000", "5000 ", "Infinity"]) {
    const r = watched(runner, { R4_RUNNER_TIMEOUT_MS: value });
    assert.equal(r.status, 1, `R4_RUNNER_TIMEOUT_MS=${JSON.stringify(value)}\n${output(r)}`);
    assert.match(r.stdout, LIMIT_REFUSED);
    assert.doesNotMatch(r.stdout, /^# tests /m, "a test ran although the limit was refused");
  }
  // 1000, the lowest accepted value, is not refused; whether the stub finishes inside 1 s is not asserted.
  assert.doesNotMatch(watched(runner, { R4_RUNNER_TIMEOUT_MS: "1000" }).stdout, LIMIT_REFUSED);
});

// The runner must stop within SIGNAL_PROMPT_MS of the signal. Its own limit is far longer than that
// and than the watchdog, so neither can stop it in time: only a working handler passes this control.
const SIGNAL_PROMPT_MS = 10 * 1000;
const SIGNAL_STUB_LIMIT_MS = 120 * 1000;

test(SIGNAL_CONTROL_NAME, { skip: !POSIX && "Windows cannot deliver SIGHUP, SIGINT or SIGTERM to a child process" }, async () => {
  for (const signal of ["SIGHUP", "SIGINT", "SIGTERM"]) {
    const pidFile = path.join(scratch("pids"), "pids");
    const child = spawnAsync(process.execPath, [rawStubRunner(hangingFile(pidFile))], {
      env: childEnv({ R4_RUNNER_TIMEOUT_MS: String(SIGNAL_STUB_LIMIT_MS) }),
      stdio: ["ignore", "pipe", "pipe"],
    });
    let text = "";
    child.stdout.on("data", (chunk) => (text += chunk));
    child.stderr.on("data", (chunk) => (text += chunk));
    const closed = new Promise((resolve) => child.on("close", (code, sig) => resolve({ code, sig })));
    const watchdog = setTimeout(() => child.kill("SIGKILL"), WATCHDOG_MS);
    let pids = [];
    try {
      pids = await recordedPids(pidFile);
      child.kill(signal);
      let prompt;
      const outcome = await Promise.race([closed, new Promise((resolve) => (prompt = setTimeout(resolve, SIGNAL_PROMPT_MS, null)))]);
      clearTimeout(prompt);
      assert.ok(outcome, `${signal}: the runner was still running ${SIGNAL_PROMPT_MS / 1000} s after the signal\n${text}`);
      const { code, sig } = outcome;
      const left = await survivors(pids);
      assert.equal(sig, null, `${signal}: the runner itself died on ${sig}\n${text}`);
      assert.equal(code, 1, `${signal}\n${text}`);
      assert.match(text, new RegExp(`problem: interrupted by ${signal}; the running test file and the processes it started were killed`));
      assert.deepEqual(left, [], `${signal}: processes of the interrupted file survived: ${left.join(", ")}`);
    } finally {
      clearTimeout(watchdog);
      if (child.exitCode === null && child.signalCode === null) {
        // Ask the runner to clean up its group before forcing it.
        child.kill("SIGTERM");
        await Promise.race([closed, sleep(5000)]);
        child.kill("SIGKILL");
      }
      await survivors(pids);
    }
  }
});
