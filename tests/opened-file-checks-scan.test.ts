// The extension module reaches `vscode` at import time; the stub must be
// installed first, exactly as extension.test.ts does.
import "./stubs/install-vscode";
import * as fs from "fs";
import { tmpdir } from "os";
import * as path from "path";
import { spawnSync } from "child_process";
import { scanFiles } from "../src/workspace";
import { defaultConfig } from "../src/config";
import { OpenedFileCheck, OpenedFileChecks, SkipReason } from "../src/walk";
import { describeOpenedFileChecks } from "../src/report";
import { workspaceScanSummary } from "../src/extension";
import { toolScan, toolListFindings, setAllowedRoots, resetSessions, ToolResult } from "../src/mcp-core";
import { test, suite, finish, assert, skip } from "./harness";

/**
 * THE CHECKS AT SCAN LEVEL: refusal accounting and reporting through the real
 * CLI (text, JSON, SARIF), the shared workspace scanner, the MCP tool and the
 * editor summary.
 *
 * The interleavings are injected into the REAL CLI PROCESS with a `-r` preload
 * that wraps one `fs` function to fire once, after the real call, on the Nth
 * call whose argument is the target path -- the bundle reads `fs` members at
 * call time, so the wrapper reaches the product's own call. Each child carries
 * a hard timeout; a timeout is a failure, never a skip. The child writes
 * whether its trigger fired (and any fixture error) to a report file the
 * parent reads, so a run that measured nothing cannot pass.
 *
 * Nothing here asserts that outside bytes can never be read. Where a platform
 * has no kernel path, the documented residual is asserted AS the residual.
 */

const CLI = path.join(__dirname, "..", "out", "cli.js");
const REL = "sub/t.txt";
const INSIDE = "inside = 1;\n";
const OUTSIDE_MARKER = "OFC_OUTSIDE_ONLY_" + "3e2d";
const KERNEL_PATH = process.platform === "linux" && fs.existsSync("/proc/self/fd");

/** A credential-shaped literal, built at runtime so nothing credential-shaped is committed. */
function token(salt: number): string {
  const a = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let out = "";
  for (let i = 0; i < 36; i++) out += a[(i * 13 + salt * 11 + 3) % a.length];
  return "ghp_" + out;
}

interface Lab { dir: string; root: string; outside: string; target: string; cred: string }

function makeLab(): Lab {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(tmpdir(), "secretloop-ofcs-")));
  const root = path.join(dir, "root");
  const outside = path.join(dir, "outside");
  fs.mkdirSync(path.join(root, "sub"), { recursive: true });
  fs.mkdirSync(outside);
  const cred = token(7);
  fs.writeFileSync(path.join(root, "sub", "t.txt"), INSIDE);
  fs.writeFileSync(path.join(root, "ok.txt"), "const ok = 1;\n");
  fs.writeFileSync(path.join(outside, "t.txt"), `token = "${cred}"\n${OUTSIDE_MARKER}\n`);
  return { dir, root, outside, target: path.join(root, "sub", "t.txt"), cred };
}

function withLab(fn: (lab: Lab) => void): void {
  const lab = makeLab();
  try {
    fn(lab);
  } finally {
    fs.rmSync(lab.dir, { recursive: true, force: true });
  }
}

/**
 * The preload. Fires `action` once, after the real `fn`, on the `nth` call
 * whose first argument resolves to the target. Reports to a file: "fired",
 * "error:<code>" or nothing (never reached).
 */
const HOOK = `
const fs = require("fs"), path = require("path");
const target = process.env.OFC_TARGET, fn = process.env.OFC_FN, nth = Number(process.env.OFC_NTH || "1");
const outside = process.env.OFC_OUTSIDE, report = process.env.OFC_REPORT;
const real = fs[fn]; let seen = 0, fired = false;
function act() {
  const sub = path.dirname(target), root = path.dirname(sub);
  fs.renameSync(sub, path.join(root, "..", "sub.moved"));
  fs.symlinkSync(outside, sub, process.platform === "win32" ? "junction" : "dir");
}
fs[fn] = function (...a) {
  const r = real.apply(this, a);
  if (!fired && typeof a[0] === "string" && path.resolve(a[0]) === target && ++seen === nth) {
    fired = true;
    try { act(); fs.writeFileSync(report, "fired"); }
    catch (e) { fs.writeFileSync(report, "error:" + String(e && e.code || e)); throw e; }
  }
  return r;
};
`;

interface ChildRun { status: number | null; stdout: string; stderr: string; report: string }

function cliWithHook(lab: Lab, fn: string, nth: number, args: string[]): ChildRun {
  const hook = path.join(lab.dir, "hook.js");
  const report = path.join(lab.dir, `report-${fn}-${nth}-${args.join("").replace(/[^a-z]/g, "")}.txt`);
  fs.writeFileSync(hook, HOOK);
  const r = spawnSync(process.execPath, ["-r", hook, CLI, ...args, "--path", lab.root, "--fail-on", "never"], {
    encoding: "utf8",
    timeout: 30000,
    env: { ...process.env, OFC_TARGET: lab.target, OFC_FN: fn, OFC_NTH: String(nth), OFC_OUTSIDE: lab.outside, OFC_REPORT: report },
  });
  assert.ok(!r.error || (r.error as NodeJS.ErrnoException).code !== "ETIMEDOUT", `the CLI child timed out (${fn} #${nth}); a timeout is a failure`);
  assert.strictEqual(r.signal, null, `child died on ${r.signal}: ${r.stderr}`);
  const rep = fs.existsSync(report) ? fs.readFileSync(report, "utf8") : "";
  // Undo the swap for the next run in the same lab.
  try {
    const sub = path.join(lab.root, "sub");
    if (fs.lstatSync(sub).isSymbolicLink()) { fs.rmSync(sub, { recursive: false }); fs.renameSync(path.join(lab.dir, "sub.moved"), sub); }
  } catch { /* nothing to undo */ }
  return { status: r.status, stdout: r.stdout, stderr: r.stderr, report: rep };
}

const PLATFORM_REFUSAL = new Set(["EPERM", "EBUSY", "EACCES", "ENOTEMPTY"]);
function requireFired(run: ChildRun, what: string): void {
  if (run.report.startsWith("error:")) {
    const code = run.report.slice("error:".length);
    if (process.platform === "win32" && PLATFORM_REFUSAL.has(code)) skip(`win32 refused the fixture step (${code}) in ${what}`);
    assert.fail(`the fixture failed in ${what}: ${run.report}; stderr: ${run.stderr}`);
  }
  assert.strictEqual(run.report, "fired", `${what}: the trigger did not fire in the CLI child, so this run measured nothing; stderr: ${run.stderr}`);
  assert.strictEqual(run.status, 0, `${what}: the CLI exited ${run.status}: ${run.stderr}`);
}

function cli(args: string[], root: string): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync("node", [CLI, ...args, "--path", root, "--fail-on", "never"], { encoding: "utf8", timeout: 30000 });
  assert.ok(!r.error, `the CLI failed to run: ${r.error}`);
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

function sums(o: OpenedFileChecks): void {
  for (const c of [o.identity, o.kernelPath]) {
    assert.strictEqual(c.verified + c.refused + c.unavailable + c.failed + c.notReached, o.opened, "every descriptor has one outcome per check");
  }
}

/** The kernel-path outcome a clean descriptor records on this host, measured. */
const KP = KERNEL_PATH ? "verified" : "unavailable";

function gitInit(dir: string): void {
  const g = (...a: string[]) => {
    const r = spawnSync("git", ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", ...a], { cwd: dir, encoding: "utf8" });
    assert.strictEqual(r.status, 0, r.stderr);
  };
  g("init", "-q");
  g("add", "-A");
  g("commit", "-q", "-m", "seed");
}

// ===========================================================================
suite("opened-file checks at scan level — the block, the sentence and the surfaces");

test("a clean working-tree scan accounts for three descriptors per file, with the block in JSON and SARIF and the clause in every format", () => {
  withLab((lab) => {
    const d = JSON.parse(cli(["scan", "--format", "json"], lab.root).stdout);
    const o: OpenedFileChecks = d.summary.coverage.openedFileChecks;
    assert.ok(o, "the JSON report carries summary.coverage.openedFileChecks for a file scan");
    // Two regular files; each is opened by the PKCS#12 probe, the archive probe
    // and the text reader -- three descriptors, each checked on its own.
    assert.strictEqual(o.opened, 6, JSON.stringify(o));
    sums(o);
    assert.strictEqual(o.identity.verified, 6);
    assert.strictEqual(o.kernelPath[KP], 6, `kernel path on ${process.platform}: ${JSON.stringify(o.kernelPath)}`);
    assert.deepStrictEqual(d.summary.coverage.limitations, []);
    assert.strictEqual(d.incomplete, false);
    assert.ok(!("openedFileChecks" in d), "descriptive only: never a top-level comparison field");
    assert.ok(d.summary.scope.endsWith(describeOpenedFileChecks(o)), d.summary.scope);

    const s = JSON.parse(cli(["scan", "--format", "sarif"], lab.root).stdout);
    assert.deepStrictEqual(s.runs[0].invocations[0].properties.openedFileChecks, o, "SARIF carries the same block");
    assert.ok(String(s.runs[0].invocations[0].properties.scope).endsWith(describeOpenedFileChecks(o)));

    const t = cli(["scan"], lab.root).stdout;
    assert.ok(t.includes(`; ${describeOpenedFileChecks(o)}.`), t);
    console.log(`    ${process.platform}: ${describeOpenedFileChecks(o)}`);
  });
});

test("a staged scan carries the block; a history scan, which never runs the readers, omits it", () => {
  withLab((lab) => {
    gitInit(lab.root);
    const staged = JSON.parse(cli(["staged", "--format", "json"], lab.root).stdout);
    // Nothing is staged after the commit, so nothing is opened -- and that is
    // stated as zero, not left absent.
    assert.deepStrictEqual(staged.summary.coverage.openedFileChecks.opened, 0);
    assert.match(staged.summary.scope, /0 descriptor\(s\) opened for content$/);
    fs.writeFileSync(path.join(lab.root, "new.txt"), "const n = 2;\n");
    spawnSync("git", ["add", "-A"], { cwd: lab.root });
    const staged2 = JSON.parse(cli(["staged", "--format", "json"], lab.root).stdout);
    assert.strictEqual(staged2.summary.coverage.openedFileChecks.opened, 3, "one staged file, three descriptors");

    const history = JSON.parse(cli(["history", "--format", "json"], lab.root).stdout);
    assert.ok(!("openedFileChecks" in history.summary.coverage), "history never opens files through the readers; the block is absent, not zero");
    assert.doesNotMatch(history.summary.scope, /descriptor\(s\) opened/);
  });
});

test("an empty tree says zero descriptors beside its zero-files sentence", () => {
  const dir = fs.mkdtempSync(path.join(tmpdir(), "secretloop-ofcs-empty-"));
  try {
    const d = JSON.parse(cli(["scan", "--format", "json"], dir).stdout);
    assert.deepStrictEqual(d.summary.coverage.openedFileChecks, {
      opened: 0,
      identity: { verified: 0, refused: 0, unavailable: 0, failed: 0, notReached: 0 },
      kernelPath: { verified: 0, refused: 0, unavailable: 0, failed: 0, notReached: 0 },
    });
    assert.strictEqual(d.summary.scope, "0 file(s) — nothing was scanned, so this is not a clean result; 0 descriptor(s) opened for content");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ===========================================================================
suite("opened-file checks at scan level — a refusal is counted once, disclosed everywhere, and nothing from the substitute is emitted (T11, T14)");

/**
 * The parent is swapped for a link to the outside directory right after the
 * FIRST lstat of the target -- the PKCS#12 probe's -- so that probe opens the
 * outside object and its identity check refuses it. The file must then be
 * refused as a whole: no fall-through to the archive probe or the text reader,
 * one `replaced` skip, one refused descriptor, and nothing of the outside
 * content in any output.
 */
function refusalOnProbe(lab: Lab, format: string[]): { run: ChildRun } {
  const run = cliWithHook(lab, "lstatSync", 1, ["scan", ...format]);
  requireFired(run, `probe refusal (${format.join(" ") || "text"})`);
  const all = run.stdout + run.stderr;
  assert.ok(!all.includes(lab.cred), "the outside credential crossed the boundary");
  assert.ok(!all.includes(OUTSIDE_MARKER), "outside content crossed the boundary");
  assert.ok(!all.includes(lab.dir), "no absolute path in the output");
  return { run };
}

test("JSON: the probe's identity refusal refuses the file -- one `replaced` limitation, incomplete, one refused descriptor, no re-open", () => {
  withLab((lab) => {
    const { run } = refusalOnProbe(lab, ["--format", "json"]);
    const d = JSON.parse(run.stdout);
    const o: OpenedFileChecks = d.summary.coverage.openedFileChecks;
    assert.deepStrictEqual(d.summary.coverage.limitations, ["1 file(s) not scanned — replaced between inspection and read"]);
    assert.strictEqual(d.incomplete, true, "a refusal is a coverage gap");
    // ok.txt: three verified descriptors. sub/t.txt: exactly ONE descriptor,
    // the refusing probe's -- the archive probe and the text reader never ran.
    assert.strictEqual(o.opened, 4, JSON.stringify(o));
    sums(o);
    assert.strictEqual(o.identity.refused, 1);
    assert.strictEqual(o.identity.verified, 3);
    assert.strictEqual(o.kernelPath.notReached, 1, "the kernel-path check is not reached after an identity refusal");
    assert.strictEqual(d.summary.scannedCount, 1);
    assert.deepStrictEqual(d.findings, []);
    assert.match(d.summary.scope, /1 file\(s\) not scanned — replaced between inspection and read; 4 descriptor\(s\) opened for content: identity 3 verified, 1 refused;/);
  });
});

test("text and SARIF: the same refusal, the same clause, the same block", () => {
  withLab((lab) => {
    const t = refusalOnProbe(lab, []).run.stdout;
    assert.match(t, /1 file\(s\) not scanned — replaced between inspection and read/);
    assert.match(t, /identity 3 verified, 1 refused/);
    const s = JSON.parse(refusalOnProbe(lab, ["--format", "sarif"]).run.stdout);
    const props = s.runs[0].invocations[0].properties;
    assert.strictEqual(props.openedFileChecks.identity.refused, 1);
    assert.match(props.scope, /replaced between inspection and read/);
    assert.deepStrictEqual(s.runs[0].results, []);
  });
});

test("a refused file cannot read as a removed finding: the comparator refuses the pair on `incomplete`, computing no difference", () => {
  // The contract end to end through the built CLI: a clean report of the tree
  // and one in which the same file was refused as `replaced`. The finding that
  // the substitute would have contributed is not "gone" -- the pair is
  // ineligible, the reason names the after side's coverage, and nothing from
  // the outside object appears in either output.
  withLab((lab) => {
    // A repository, so the reports carry `root` and the only reason left to
    // refuse the pair is the coverage. Enumeration then goes through git, and
    // the readers' lstat order is unchanged.
    gitInit(lab.root);
    fs.writeFileSync(path.join(lab.dir, "before.json"), cli(["scan", "--format", "json"], lab.root).stdout);
    const refused = refusalOnProbe(lab, ["--format", "json"]).run;
    fs.writeFileSync(path.join(lab.dir, "after.json"), refused.stdout);
    const before = JSON.parse(fs.readFileSync(path.join(lab.dir, "before.json"), "utf8"));
    const after = JSON.parse(refused.stdout);
    assert.strictEqual(before.incomplete, false);
    assert.strictEqual(after.incomplete, true);
    for (const field of ["toolVersion", "root", "configDigest", "ruleSetDigest", "scopeDigest", "binaryDigest"]) {
      assert.strictEqual(before[field], after[field], `${field} must not move on a refusal; it is the coverage that changed`);
    }
    const r = spawnSync("node", [CLI, "compare", path.join(lab.dir, "before.json"), path.join(lab.dir, "after.json"), "--format", "json"], { encoding: "utf8", timeout: 30000 });
    assert.strictEqual(r.status, 3, `an ineligible pair exits 3: ${r.stderr}`);
    const c = JSON.parse(r.stdout);
    assert.strictEqual(c.comparable, false);
    assert.deepStrictEqual(c.reasons.map((x: { code: string; side: string; field?: string }) => [x.code, x.side, x.field]), [["incomplete-coverage", "after", "incomplete"]]);
    assert.ok(!("noLongerObserved" in c) && !("new" in c), "no difference keys at all beside an incomparable verdict");
    assert.ok(!(r.stdout + r.stderr).includes(lab.cred) && !(r.stdout + r.stderr).includes(OUTSIDE_MARKER));
  });
});

test("separate opens are checked separately: probes that verified do not vouch for the text reader's own descriptor", () => {
  // The swap lands after the THIRD lstat of the target: the text reader's
  // identity capture. The two probes before it verified their own descriptors
  // on the inside object; the text reader's open resolves to the outside
  // object and is refused on its own evidence.
  withLab((lab) => {
    const run = cliWithHook(lab, "lstatSync", 3, ["scan", "--format", "json"]);
    requireFired(run, "text-reader refusal");
    const d = JSON.parse(run.stdout);
    const o: OpenedFileChecks = d.summary.coverage.openedFileChecks;
    assert.strictEqual(o.opened, 6, JSON.stringify(o));
    sums(o);
    assert.strictEqual(o.identity.verified, 5, "the two probes' descriptors and ok.txt's three");
    assert.strictEqual(o.identity.refused, 1, "the text reader's descriptor, on its own");
    assert.deepStrictEqual(d.summary.coverage.limitations, ["1 file(s) not scanned — replaced between inspection and read"]);
    assert.ok(!(run.stdout + run.stderr).includes(lab.cred));
  });
});

test("the realpath-to-identity gap at the text reader: refused by the kernel path on Linux, the documented residual elsewhere (T6 at scan level)", () => {
  // The swap lands after the text reader's realpath -- the FOURTH realpath
  // of the target: the walker's containment check, the PKCS#12 probe, the
  // archive probe, then the text reader -- so its lstat captures the OUTSIDE
  // object's identity and the identity check passes. Only the kernel path
  // refuses this. Where there is none, the outside content is scanned and
  // reported under the inside name -- the measured residual, asserted as
  // such so a reader of this test is not told otherwise.
  withLab((lab) => {
    const run = cliWithHook(lab, "realpathSync", 4, ["scan", "--format", "json"]);
    requireFired(run, "realpath-gap");
    const d = JSON.parse(run.stdout);
    const o: OpenedFileChecks = d.summary.coverage.openedFileChecks;
    sums(o);
    assert.strictEqual(o.opened, 6);
    assert.strictEqual(o.identity.verified, 6, "the identity check cannot see this case: it captured the substitute");
    if (KERNEL_PATH) {
      assert.strictEqual(o.kernelPath.refused, 1, JSON.stringify(o.kernelPath));
      assert.deepStrictEqual(d.summary.coverage.limitations, ["1 file(s) not scanned — resolved outside the scan root"]);
      assert.strictEqual(d.incomplete, true);
      assert.deepStrictEqual(d.findings, []);
      assert.ok(!(run.stdout + run.stderr).includes(lab.cred), "the kernel-path refusal must keep the outside credential out");
    } else {
      assert.strictEqual(o.kernelPath.unavailable, 6);
      assert.deepStrictEqual(d.summary.coverage.limitations, [], "no check observed anything; the report is complete and wrong about this file");
      const files = d.findings.map((f: { file: string }) => f.file);
      assert.deepStrictEqual(files, [REL], `RESIDUAL on ${process.platform}: the outside credential is reported under the inside name`);
      console.log(`    RESIDUAL on ${process.platform}: a parent swap in the text reader's realpath-to-lstat gap was read (no kernel path); the block says "kernel path 6 unavailable"`);
    }
  });
});

// ===========================================================================
suite("opened-file checks at scan level — the shared scanner, the MCP tool and the editor summary");

/** In-process wrapper: fires once, after the real call, on the nth matching call. */
function fireAfter(name: "lstatSync", target: string, nth: number, action: () => void) {
  const real = (fs as any)[name];
  const state = { fired: false, seen: 0, error: null as null | string };
  (fs as any)[name] = function (this: unknown, ...args: unknown[]) {
    const r = real.apply(this, args);
    if (!state.fired && typeof args[0] === "string" && path.resolve(args[0]) === target && ++state.seen === nth) {
      state.fired = true;
      try { action(); } catch (e) { state.error = String((e as NodeJS.ErrnoException).code ?? e); throw e; }
    }
    return r;
  };
  return { state, restore: () => { (fs as any)[name] = real; } };
}
function swapParent(lab: Lab): void {
  fs.renameSync(path.join(lab.root, "sub"), path.join(lab.dir, "sub.moved"));
  fs.symlinkSync(lab.outside, path.join(lab.root, "sub"), process.platform === "win32" ? "junction" : "dir");
}
function platformSkip(state: { error: null | string }, what: string): void {
  if (state.error && process.platform === "win32" && PLATFORM_REFUSAL.has(state.error)) skip(`win32 refused ${what} (${state.error})`);
  assert.strictEqual(state.error, null, `fixture failed: ${state.error}`);
}

test("scanFiles: a probe refusal is reported once through onSkipped as `replaced`, with one record for that file and no fall-through -- even when a buffer is offered", () => {
  withLab((lab) => {
    const skipped: Array<[SkipReason, string]> = [];
    const checks: Array<[OpenedFileCheck, string]> = [];
    const w = fireAfter("lstatSync", lab.target, 1, () => swapParent(lab));
    let scanned;
    try {
      scanned = scanFiles(lab.root, ["ok.txt", REL], { ...defaultConfig, maxFileSizeBytes: 1_000_000 }, {
        // An open buffer for the file whose disk object was substituted. The
        // refusal stands: the buffer is not scanned and the skip is reported,
        // because a positive observation on the disk object is not something a
        // buffer can answer for.
        textFor: (p) => (p === REL ? "buffer = 1;\n" : undefined),
        onSkipped: (reason, relPath) => skipped.push([reason, relPath]),
        onOpenedFileCheck: (check, relPath) => checks.push([check, relPath]),
      });
    } finally {
      w.restore();
    }
    platformSkip(w.state, "the parent swap");
    assert.strictEqual(w.state.fired, true, "the trigger did not fire");
    assert.deepStrictEqual(skipped, [["replaced", REL]]);
    assert.deepStrictEqual(scanned.map((s) => s.path), ["ok.txt"]);
    assert.deepStrictEqual(checks.filter(([, p]) => p === REL).map(([c]) => c), [{ identity: "refused", kernelPath: "not-reached" }]);
    assert.strictEqual(checks.filter(([, p]) => p === "ok.txt").length, 3);
  });
});

function payload(r: ToolResult): any {
  assert.strictEqual(r.ok, true, JSON.stringify(r));
  return (r as { ok: true; payload: any }).payload;
}

test("MCP: the scope object carries the block and the statement carries the clause; a refusal is counted and nothing outside is emitted; list_findings carries the same scope", () => {
  withLab((lab) => {
    resetSessions();
    setAllowedRoots([lab.root]);
    const clean = payload(toolScan({ path: lab.root }));
    assert.strictEqual(clean.scope.openedFileChecks.opened, 6);
    assert.ok(clean.scope.statement.endsWith(`; ${describeOpenedFileChecks(clean.scope.openedFileChecks)}.`), clean.scope.statement);

    resetSessions();
    const w = fireAfter("lstatSync", lab.target, 1, () => swapParent(lab));
    let p;
    try {
      p = payload(toolScan({ path: lab.root }));
    } finally {
      w.restore();
    }
    platformSkip(w.state, "the parent swap");
    assert.strictEqual(w.state.fired, true);
    assert.strictEqual(p.scope.openedFileChecks.identity.refused, 1, JSON.stringify(p.scope.openedFileChecks));
    assert.strictEqual(p.scope.openedFileChecks.opened, 4);
    assert.match(p.scope.statement, /1 file\(s\) not scanned — replaced between inspection and read; 4 descriptor\(s\) opened for content/);
    const emitted = JSON.stringify(p);
    assert.ok(!emitted.includes(lab.cred) && !emitted.includes(OUTSIDE_MARKER), "outside content reached the MCP payload");
    // The payload's own `root` field is the caller's path by design; the scope
    // object and the findings must carry none.
    assert.ok(!JSON.stringify(p.scope).includes(lab.dir) && !JSON.stringify(p.findings).includes(lab.dir), "an absolute path reached the scope or a finding");
    const list = payload(toolListFindings({ path: lab.root }));
    assert.deepStrictEqual(list.scope, p.scope, "list_findings carries the scan's scope, block included");
  });
});

test("the editor summary appends the clause when handed the accounting, and is byte-identical without it", () => {
  const acc: OpenedFileChecks = {
    opened: 6,
    identity: { verified: 6, refused: 0, unavailable: 0, failed: 0, notReached: 0 },
    kernelPath: { verified: 0, refused: 0, unavailable: 6, failed: 0, notReached: 0 },
  };
  assert.strictEqual(workspaceScanSummary([], 2), "SecretLoop: no secrets found across 2 file(s).");
  assert.strictEqual(workspaceScanSummary([], 2, 0, 0, 0, undefined, 0, 0, 0), "SecretLoop: no secrets found across 2 file(s).");
  assert.strictEqual(
    workspaceScanSummary([], 2, 0, 0, 0, undefined, 0, 0, 0, acc),
    "SecretLoop: no secrets found across 2 file(s); 6 descriptor(s) opened for content: identity 6 verified; kernel path 6 unavailable."
  );
});

finish();
