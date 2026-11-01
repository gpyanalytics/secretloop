#!/usr/bin/env node
"use strict";
/*
 * Runs the R4 comparator tests and accounts for every result they report. Node built-ins only.
 *
 *   node run-comparator-tests.js                 routine CI and local runs (npm run test:comparator)
 *   node run-comparator-tests.js --require-n10   release checklist (npm run test:comparator:n10)
 *
 * A test runner that exits 0 says only that nothing it ran failed. This checks what ran:
 *   - NODE_OPTIONS must be empty. Test-runner options set there (--test-name-pattern,
 *     --test-skip-pattern, --test-only, --test-shard) remove tests from a run without failing them.
 *   - Every reported result is a pass or an allowed skip, and the results add up to the reported
 *     totals. A skip is allowed only by exact test name: the three historical N10 cases in a routine
 *     run; and on Windows the symbolic-link controls, where creating a link needs privilege, and the
 *     guard file's POSIX signal control, since Windows cannot deliver those signals to a child.
 *   - With --require-n10 the three N10 cases may not skip, and each must append its id to a fresh
 *     receipt file after its assertions pass: exactly those three ids, once each. That is evidence the
 *     cases ran, separate from the exit code and from the report.
 *   - Each file runs under a wall-clock limit, 300 s unless R4_RUNNER_TIMEOUT_MS sets another value
 *     from 1000 to 3600000; the summary header prints the limit in force. A file that hits it or
 *     overflows its output fails, and so does a run interrupted by SIGINT, SIGTERM or SIGHUP.
 *
 * Cleanup. On POSIX each node --test child leads its own process group. On a timeout, an overflow
 * or one of those three signals the whole group is killed, and a process still in the group after
 * a normal exit is reported and killed. On Windows the tree is killed with taskkill /T /F, and no
 * check is made for processes left behind. Not covered, on any platform:
 *   - SIGKILL of this runner, or a crash of it: its handlers never run, so the running file's
 *     processes are left with no limit.
 *   - A descendant that leaves the group on purpose (setsid, or a detached child): it can outlive
 *     the run, even a passing one.
 *   - A nested run of this runner stays in the outer group, but its own node --test child leads a
 *     separate group that an outer kill does not reach. Killing the nested runner leaves that group
 *     with no limit.
 *
 * Exit codes: 0 every check held, 1 any check failed, 64 usage error.
 */
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawn, spawnSync } = require("child_process");

const MAIN = "compare-fail-closed.test.js";
const GUARD = "n10-guard.test.js";
const N10_CASES = ["n10-reproduction", "n10-without-reproduction", "n10-tamper-refused"];
const N10_NAMES = [
  "N10 reproduction: PASS-REPRODUCTION, 27 recorded differences, zero finding-level differences, frozen evidence unchanged",
  "N10 without the reproduction is FAIL, with 27 unapproved metadata differences",
  "N10 reproduction refuses a changed finding in a scratch copy: the pinned bytes no longer match",
];
const SYMLINK_NAMES = [
  "F4: a symlinked SHA256SUMS BLOCKs",
  "F4: a symlinked manifest BLOCKs",
  "F4: a symlinked report file BLOCKs",
  "F4: a symlinked report root BLOCKs",
  "same directory: a symlink to the other side BLOCKs",
];
// The guard control that sends POSIX signals to a runner. Windows cannot deliver them to a child.
const SIGNAL_CONTROL_NAME = "runner: SIGHUP, SIGINT and SIGTERM each fail the run and kill the running file's processes";
const COUNTS = ["tests", "pass", "fail", "cancelled", "skipped", "todo"];
const DEFAULT_LIMIT_MS = 300 * 1000;
const MAX_OUTPUT = 64 * 1024 * 1024;
const POSIX = process.platform !== "win32";

// Kills a child and every process it started. On POSIX the child leads its own process group.
function killTree(pid) {
  if (POSIX) {
    try {
      process.kill(-pid, "SIGKILL");
    } catch {
      // The group is already gone.
    }
  } else {
    spawnSync("taskkill", ["/pid", String(pid), "/T", "/F"], { stdio: "ignore", windowsHide: true });
  }
}

// Whether any process is left in the POSIX process group the child led.
function groupAlive(pid) {
  try {
    process.kill(-pid, 0);
    return true;
  } catch (err) {
    return err.code === "EPERM";
  }
}

// Waits up to graceMs for the group to empty, since killed processes take a moment to be reaped.
async function groupLingers(pid, graceMs) {
  for (const end = Date.now() + graceMs; Date.now() < end; ) {
    if (!groupAlive(pid)) return false;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  return groupAlive(pid);
}

// Runs one test file under node --test with a wall-clock limit. The result carries what account()
// reads: status, signal, stdout, stderr and error, plus what went wrong with the run itself.
function runFile(file, env, limitMs, active) {
  return new Promise((resolve) => {
    const run = { status: null, signal: null, stdout: "", stderr: "", error: null, timedOut: false, overflow: false, leftBehind: false, limitMs, ms: 0 };
    const out = [];
    const err = [];
    let bytes = 0;
    let settled = false;
    const started = Date.now();
    let child;
    try {
      child = spawn(process.execPath, ["--test", "--test-reporter=tap", path.join(__dirname, file)], {
        env,
        detached: POSIX,
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true,
      });
    } catch (e) {
      run.error = e;
      return resolve(run);
    }
    const settle = async () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      active.child = null;
      run.ms = Date.now() - started;
      run.stdout = Buffer.concat(out).toString("utf8");
      run.stderr = Buffer.concat(err).toString("utf8");
      if (POSIX && child.pid !== undefined && groupAlive(child.pid)) {
        if (!run.timedOut && !run.overflow) run.leftBehind = true;
        killTree(child.pid);
        if (await groupLingers(child.pid, 2000)) run.leftBehind = true;
      }
      resolve(run);
    };
    const take = (sink) => (chunk) => {
      bytes += chunk.length;
      if (bytes <= MAX_OUTPUT) sink.push(chunk);
      else if (!run.overflow) {
        run.overflow = true;
        killTree(child.pid);
      }
    };
    child.stdout.on("data", take(out));
    child.stderr.on("data", take(err));
    const timer = setTimeout(() => {
      run.timedOut = true;
      killTree(child.pid);
    }, limitMs);
    active.child = child;
    child.on("error", (e) => {
      run.error = e;
      if (child.pid === undefined) settle();
    });
    child.on("close", (status, signal) => {
      run.status = status;
      run.signal = signal;
      settle();
    });
  });
}

// The per-file limit: the default, or R4_RUNNER_TIMEOUT_MS when it is a whole number of milliseconds
// from 1000 to 3600000. Anything else is refused, so the limit can be changed but never removed.
function limitFrom(value) {
  if (value === undefined) return { limitMs: DEFAULT_LIMIT_MS };
  const ms = /^\d+$/.test(value) ? Number(value) : NaN;
  if (ms >= 1000 && ms <= 3600 * 1000) return { limitMs: ms };
  return { problem: `R4_RUNNER_TIMEOUT_MS must be a whole number of milliseconds from 1000 to 3600000, not ${JSON.stringify(value)}` };
}

// Reverses Node's TAP escaping of a test name. Node writes a control character as a backslash and a
// letter and then doubles every backslash, so a single backslash in its output is always followed by
// another backslash or by #. Exact for names with no control characters, which file paths and these
// test names never contain.
function tapUnescape(text) {
  return text.replace(/\\([\\#])/g, "$1");
}

// The top-level results and the summary counts of a TAP report. Node prints top-level results at
// column 0; diagnostics are indented. A result's indented YAML block is read only for the failure
// type, which is how TAP marks a cancelled test apart from a failed one.
function parseTap(text) {
  const results = [];
  const counts = {};
  for (const line of text.split(/\r?\n/)) {
    const r = /^(ok|not ok) \d+ - (.*)$/.exec(line);
    if (r) {
      const d = / # (SKIP|TODO)\b ?(.*)$/i.exec(r[2]);
      results.push({
        ok: r[1] === "ok",
        name: tapUnescape(d ? r[2].slice(0, d.index) : r[2]),
        directive: d ? d[1].toUpperCase() : null,
        reason: d ? d[2] : "",
        cancelled: false,
      });
      continue;
    }
    if (results.length > 0 && /^\s+failureType: '?cancelledByParent'?$/.test(line)) {
      results[results.length - 1].cancelled = true;
      continue;
    }
    const c = /^# (\w+) (\d+)$/.exec(line);
    if (c && COUNTS.includes(c[1])) counts[c[1]] = Number(c[2]);
  }
  return { results, counts };
}

// Whether a reported name is the test file itself rather than a test in it. Node reports a file as a
// result of its own, named by its path, when the file registers no tests or fails as a whole. The
// comparison is by resolved path, so an absolute or a cwd-relative spelling both match.
function isFileResult(name, file) {
  const a = path.resolve(name);
  const b = path.resolve(__dirname, file);
  return process.platform === "win32" ? a.toLowerCase() === b.toLowerCase() : a === b;
}

// Checks one file's run against its allowed skips. Appends what is wrong to problems.
function account(file, run, allowedSkips, problems) {
  const { results, counts } = parseTap(run.stdout || "");
  if (run.error) problems.push(`${file}: could not run: ${run.error.message}`);
  if (run.timedOut) problems.push(`${file}: timed out after ${run.limitMs / 1000} s; node --test and the processes it started were killed`);
  if (run.overflow) problems.push(`${file}: output exceeded ${MAX_OUTPUT} bytes; node --test and the processes it started were killed`);
  if (run.leftBehind) problems.push(`${file}: processes were still running in its process group after node --test exited; they were killed`);
  if (run.status !== 0) problems.push(`${file}: node --test exited ${run.status === null ? `on signal ${run.signal}` : run.status}`);
  for (const key of COUNTS) {
    if (!Number.isInteger(counts[key])) problems.push(`${file}: the report has no "# ${key}" count`);
  }
  if (counts.tests !== results.length) problems.push(`${file}: ${results.length} results reported, but the summary says ${counts.tests}`);
  if (counts.fail > 0 || counts.cancelled > 0 || counts.todo > 0) {
    problems.push(`${file}: summary reports fail ${counts.fail}, cancelled ${counts.cancelled}, todo ${counts.todo}`);
  }
  // The file's own result is never a test: it is how Node reports a file with no tests, which is a
  // passing "ok" line, or a file that failed as a whole.
  const genuine = [];
  for (const r of results) {
    if (!isFileResult(r.name, file)) genuine.push(r);
    else if (!r.ok) problems.push(`${file}: the file failed as a whole`);
  }
  if (genuine.length === 0) problems.push(`${file}: no test results were reported; a file that registers no tests is not a pass`);
  const tally = { passed: 0, failed: 0, cancelled: 0, todo: 0, skipped: [] };
  for (const r of genuine) {
    if (!r.ok && r.cancelled) {
      tally.cancelled++;
      problems.push(`${file}: cancelled: ${r.name}`);
    } else if (!r.ok) {
      tally.failed++;
      problems.push(`${file}: not ok: ${r.name}`);
    } else if (r.directive === "TODO") {
      tally.todo++;
      problems.push(`${file}: todo: ${r.name}`);
    } else if (r.directive === "SKIP") {
      tally.skipped.push(r.name);
      if (!allowedSkips.includes(r.name)) problems.push(`${file}: skip not allowed: ${r.name} (${r.reason})`);
    } else tally.passed++;
  }
  if (counts.skipped !== tally.skipped.length) problems.push(`${file}: ${tally.skipped.length} skips reported, but the summary says ${counts.skipped}`);
  return { file, tests: genuine.length, ...tally, ms: run.ms };
}

function finish(mode, summaries, problems) {
  const lines = [`R4 comparator tests (${mode}): ${problems.length === 0 ? "PASS" : "FAIL"}`];
  for (const s of summaries) {
    const others = [s.failed && `${s.failed} failed`, s.cancelled && `${s.cancelled} cancelled`, s.todo && `${s.todo} todo`].filter(Boolean);
    lines.push(
      `  ${s.file}: ${s.tests} tests, ${s.passed} passed${others.map((o) => `, ${o}`).join("")}, ${s.skipped.length} skipped` +
        (s.skipped.length ? `: ${s.skipped.join("; ")}` : "") +
        ` [${(s.ms / 1000).toFixed(1)} s]`
    );
  }
  for (const p of problems) lines.push(`  problem: ${p}`);
  process.stdout.write(lines.join("\n") + "\n");
  return problems.length === 0 ? 0 : 1;
}

async function main(argv) {
  const requireN10 = argv.length === 1 && argv[0] === "--require-n10";
  if (argv.length > 0 && !requireN10) {
    process.stderr.write("usage: node run-comparator-tests.js [--require-n10]\n");
    return 64;
  }
  const mode = requireN10 ? "release checklist, N10 required" : "routine";
  if ((process.env.NODE_OPTIONS || "").trim() !== "") {
    return finish(mode, [], [
      `NODE_OPTIONS is set (${JSON.stringify(process.env.NODE_OPTIONS)}); unset it, since test-runner options set there can remove tests from the run without failing them`,
    ]);
  }
  const { limitMs, problem } = limitFrom(process.env.R4_RUNNER_TIMEOUT_MS);
  if (problem) return finish(mode, [], [problem]);
  const label = `${mode}, limit ${limitMs / 1000} s per file`;
  const env = { ...process.env };
  // Set by an enclosing node --test; it would make the child report to a parent that is not there.
  delete env.NODE_TEST_CONTEXT;
  delete env.R4_N10_RECEIPT;
  const win = process.platform === "win32";
  const platformSkips = win ? SYMLINK_NAMES : [];
  const plan = requireN10
    ? [[MAIN, platformSkips]]
    : [[MAIN, [...N10_NAMES, ...platformSkips]], [GUARD, win ? [SIGNAL_CONTROL_NAME] : []]];
  const summaries = [];
  const problems = [];
  let receiptDir = null;
  // An interrupt or hangup kills the running child's tree. On POSIX the child is in its own process
  // group, so a terminal's Ctrl-C or hangup would not otherwise reach it.
  const active = { child: null };
  let interrupted = null;
  const onSignal = (signal) => {
    interrupted = signal;
    if (active.child) killTree(active.child.pid);
  };
  process.on("SIGINT", onSignal);
  process.on("SIGTERM", onSignal);
  process.on("SIGHUP", onSignal);
  try {
    if (requireN10) {
      receiptDir = fs.mkdtempSync(path.join(os.tmpdir(), "r4-n10-receipt-"));
      env.R4_REQUIRE_N10 = "1";
      env.R4_N10_RECEIPT = path.join(receiptDir, "receipt.txt");
    }
    for (const [file, allowed] of plan) {
      if (interrupted) break;
      const run = await runFile(file, env, limitMs, active);
      process.stdout.write(run.stdout);
      process.stderr.write(run.stderr);
      summaries.push(account(file, run, allowed, problems));
    }
    if (interrupted) problems.push(`interrupted by ${interrupted}; the running test file and the processes it started were killed`);
    if (requireN10) {
      let ids = [];
      try {
        ids = fs.readFileSync(env.R4_N10_RECEIPT, "utf8").split("\n").filter((line) => line !== "");
      } catch (err) {
        if (err.code !== "ENOENT") problems.push(`cannot read the N10 receipt: ${err.code || err.message}`);
      }
      if ([...ids].sort().join("\n") !== [...N10_CASES].sort().join("\n")) {
        problems.push(`the N10 receipt holds [${ids.join(", ")}], not exactly [${N10_CASES.join(", ")}] once each: the historical cases did not all run to completion`);
      }
    }
  } finally {
    process.removeListener("SIGINT", onSignal);
    process.removeListener("SIGTERM", onSignal);
    process.removeListener("SIGHUP", onSignal);
    if (receiptDir) fs.rmSync(receiptDir, { recursive: true, force: true });
  }
  return finish(label, summaries, problems);
}

if (require.main === module) {
  main(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code;
    },
    (err) => {
      process.stdout.write(`R4 comparator tests: FAIL\n  problem: the runner itself failed: ${err && err.stack ? err.stack : err}\n`);
      process.exitCode = 1;
    }
  );
}
