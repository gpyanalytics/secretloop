import * as fs from "fs";
import { tmpdir } from "os";
import * as path from "path";
import {
  readTextFileResult,
  readBinaryCandidate,
  kernelPathInside,
  emptyOpenedFileChecks,
  recordOpenedFileCheck,
  OpenedFileCheck,
  OpenedFileChecks,
} from "../src/walk";
import { defaultConfig } from "../src/config";
import { describeScope, describeOpenedFileChecks, describeCheckCounts } from "../src/report";
import { describeScope as mcpDescribeScope } from "../src/mcp-core";
import { coverageLimitations } from "../src/report-metadata";
import { test, suite, finish, assert, skip } from "./harness";

/**
 * F-1 CONCERN A, SLICE 2 — the checks that run on the OPENED descriptor before
 * its first read, and the accounting of what they did.
 *
 * WHAT THESE TESTS DRIVE: the real `readTextFileResult` and
 * `readBinaryCandidate`. The interleavings are produced by wrapping ONE
 * function on the real `fs` module so that it fires ONCE, after the real call,
 * on the exact path the reader is working on -- the same technique the FIFO
 * swap cases use, in-process here because nothing in these cases can block.
 * Every case asserts that its trigger FIRED: a base build that never reaches a
 * seam would otherwise pass by measuring nothing.
 *
 * THE EXPECTATIONS ARE THE MEASURED ONES, per platform, from the frozen records
 * `f1-containment-design-review` and its timing addendum. Where a platform
 * cannot construct a case (Windows refuses to move the parent of an open
 * file), the case SKIPS with the refusing call and code; a fixture failure of
 * any other kind FAILS.
 *
 * WHAT IS CLAIMED, AND ONLY THAT. Linux with procfs: no bytes are read from an
 * object whose kernel-recorded location, at the check that immediately
 * precedes the first read, is outside the root. Every platform: no bytes are
 * read from an object other than the one inspected one syscall before the
 * open. NOT claimed, and asserted here as the residual it is: location at the
 * open (MI1/MI2 are accepted by design), location throughout the read (MO1 is
 * read by design), the parent case without a kernel path.
 */

const INSIDE = "INSIDE_CONTENT_" + "9c1e";
const OUTSIDE = "OUTSIDE_CONTENT_" + "4f7a";
const REL = "sub/t.txt";

function cfg() {
  return { ...defaultConfig, maxFileSizeBytes: 1_000_000 };
}

interface Lab {
  dir: string;
  root: string;
  outside: string;
  /** `<root>/sub/t.txt` as the reader resolves it. */
  target: string;
  /** `<outside>/t.txt`. */
  outsideFile: string;
}

function withLab(fn: (lab: Lab) => void): void {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(tmpdir(), "secretloop-ofc-")));
  try {
    const root = path.join(dir, "root");
    const outside = path.join(dir, "outside");
    fs.mkdirSync(path.join(root, "sub"), { recursive: true });
    fs.mkdirSync(outside);
    fs.writeFileSync(path.join(root, "sub", "t.txt"), INSIDE);
    fs.writeFileSync(path.join(outside, "t.txt"), OUTSIDE);
    fn({ dir, root, outside, target: path.join(root, "sub", "t.txt"), outsideFile: path.join(outside, "t.txt") });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/** Whether the kernel-path check can run here: measured, not assumed from the platform. */
const KERNEL_PATH = process.platform === "linux" && fs.existsSync("/proc/self/fd");
const KP_EXPECTED = KERNEL_PATH ? "verified" : "unavailable";

/**
 * Wraps `fs[name]` so that `action` runs ONCE, after the first real call whose
 * first argument satisfies `match`. Restored by the returned function; `fired`
 * says whether the trigger reached the reader's call at all.
 */
type FsName = "lstatSync" | "openSync" | "fstatSync" | "realpathSync" | "readlinkSync" | "statSync";
function fireAfter(name: FsName, match: (arg: unknown) => boolean, action: () => void) {
  const real = (fs as any)[name];
  const state = { fired: false, error: null as null | { call: string; code: string } };
  (fs as any)[name] = function (this: unknown, ...args: unknown[]) {
    const r = real.apply(this, args);
    if (!state.fired && match(args[0])) {
      state.fired = true;
      try {
        action();
      } catch (e) {
        state.error = { call: name, code: String((e as NodeJS.ErrnoException).code ?? e) };
        throw e;
      }
    }
    return r;
  };
  return { state, restore: () => { (fs as any)[name] = real; } };
}

/** Runs `fn` with every wrapper restored afterwards, whatever happens. */
function withWraps<T>(wraps: Array<{ restore: () => void }>, fn: () => T): T {
  try {
    return fn();
  } finally {
    for (const w of wraps.reverse()) w.restore();
  }
}

/** A fixture step Windows refuses on an open handle is a platform property, recorded as a skip. */
const PLATFORM_REFUSAL = new Set(["EPERM", "EBUSY", "EACCES", "ENOTEMPTY"]);
function platformSkip(state: { error: null | { call: string; code: string } }, what: string): void {
  if (state.error && process.platform === "win32" && PLATFORM_REFUSAL.has(state.error.code)) {
    skip(`win32 refused ${what} at ${state.error.call} (${state.error.code}); the case cannot be constructed here`);
  }
  assert.strictEqual(state.error, null, `the fixture failed: ${JSON.stringify(state.error)}`);
}

/** A trigger that did not fire measured nothing. */
function assertFired(state: { fired: boolean }, what: string): void {
  assert.strictEqual(state.fired, true, `${what}: the trigger did not fire, so this run measured nothing`);
}

/** Replaces `<root>/sub` with a link to `to`. A junction on Windows: it needs no privilege there. */
function swapParent(lab: Lab, to: string): void {
  fs.renameSync(path.join(lab.root, "sub"), path.join(lab.dir, "sub.moved"));
  fs.symlinkSync(to, path.join(lab.root, "sub"), process.platform === "win32" ? "junction" : "dir");
}

function collect(): { checks: OpenedFileCheck[]; hooks: { onOpenedFileCheck: (c: OpenedFileCheck) => void; afterOpen?: () => void } } {
  const checks: OpenedFileCheck[] = [];
  return { checks, hooks: { onOpenedFileCheck: (c) => checks.push(c) } };
}

function fdProbe(dir: string): number {
  const fd = fs.openSync(dir, "r");
  fs.closeSync(fd);
  return fd;
}

// ===========================================================================
suite("opened-file checks — controls (T1)");

test("a regular file is read, and its one descriptor records identity verified and the measured kernel-path outcome", () => {
  withLab((lab) => {
    const { checks, hooks } = collect();
    const r = readTextFileResult(lab.root, REL, cfg(), hooks);
    assert.strictEqual((r as { text: string }).text, INSIDE);
    assert.deepStrictEqual(checks, [{ identity: "verified", kernelPath: KP_EXPECTED }]);
    console.log(`    kernel-path check on ${process.platform}: ${KP_EXPECTED} (measured: /proc/self/fd ${KERNEL_PATH ? "present" : "absent"})`);
  });
});

test("an in-root symlink is still read by the text path and still refused, unopened, by the binary gate", () => {
  withLab((lab) => {
    fs.symlinkSync(lab.target, path.join(lab.root, "link.txt"));
    const t = collect();
    assert.strictEqual((readTextFileResult(lab.root, "link.txt", cfg(), t.hooks) as { text: string }).text, INSIDE);
    assert.strictEqual(t.checks.length, 1, "one descriptor, one record");
    const b = collect();
    assert.strictEqual((readBinaryCandidate(lab.root, "link.txt", cfg(), undefined, 16, b.hooks) as { skipped: string }).skipped, "not-a-file");
    assert.deepStrictEqual(b.checks, [], "the non-dereferencing gate refused before any open, so nothing was recorded");
  });
});

test("a static outside symlink is refused before any open, by both readers, with no descriptor recorded", () => {
  withLab((lab) => {
    fs.symlinkSync(lab.outsideFile, path.join(lab.root, "l.txt"));
    const t = collect();
    assert.strictEqual((readTextFileResult(lab.root, "l.txt", cfg(), t.hooks) as { skipped: string }).skipped, "outside");
    const b = collect();
    assert.strictEqual((readBinaryCandidate(lab.root, "l.txt", cfg(), undefined, 16, b.hooks) as { skipped: string }).skipped, "outside");
    assert.deepStrictEqual([...t.checks, ...b.checks], []);
  });
});

// ===========================================================================
suite("opened-file checks — the identity check refuses every post-capture substitution (T2, T3, T4)");

test("T2 A1': the final component replaced by an outside symlink after the identity capture is refused unread", () => {
  withLab((lab) => {
    const { checks, hooks } = collect();
    const w = fireAfter("lstatSync", (a) => String(a) === lab.target, () => {
      fs.unlinkSync(lab.target);
      fs.symlinkSync(lab.outsideFile, lab.target);
    });
    const r = withWraps([w], () => readTextFileResult(lab.root, REL, cfg(), hooks));
    platformSkip(w.state, "replacing the inspected name");
    assertFired(w.state, "A1'");
    assert.strictEqual((r as { skipped: string }).skipped, "replaced");
    assert.deepStrictEqual(checks, [{ identity: "refused", kernelPath: "not-reached" }]);
  });
});

test("T3 A2': the parent replaced by an outside link after the identity capture is refused unread", () => {
  withLab((lab) => {
    const { checks, hooks } = collect();
    const w = fireAfter("lstatSync", (a) => String(a) === lab.target, () => swapParent(lab, lab.outside));
    const r = withWraps([w], () => readTextFileResult(lab.root, REL, cfg(), hooks));
    platformSkip(w.state, "replacing the parent directory");
    assertFired(w.state, "A2'");
    assert.strictEqual((r as { skipped: string }).skipped, "replaced");
    assert.deepStrictEqual(checks, [{ identity: "refused", kernelPath: "not-reached" }]);
  });
});

test("T4 SB: swapped out before the open and back after it is refused -- the descriptor holds the substitute", () => {
  // Rejects a stat-before/stat-after "identity": the NAME looks unchanged at
  // both stats; the OBJECT behind the descriptor is the outside file.
  withLab((lab) => {
    const { checks, hooks } = collect();
    const parked = path.join(lab.root, "sub", "orig.moved");
    const swapIn = fireAfter("lstatSync", (a) => String(a) === lab.target, () => {
      fs.renameSync(lab.target, parked);
      fs.renameSync(lab.outsideFile, lab.target);
    });
    const swapBack = fireAfter("openSync", (a) => String(a) === lab.target, () => {
      fs.renameSync(lab.target, lab.outsideFile);
      fs.renameSync(parked, lab.target);
    });
    const r = withWraps([swapIn, swapBack], () => readTextFileResult(lab.root, REL, cfg(), hooks));
    platformSkip(swapIn.state, "swapping the file out");
    platformSkip(swapBack.state, "swapping the open file back");
    assertFired(swapIn.state, "SB swap-in");
    assertFired(swapBack.state, "SB swap-back");
    assert.strictEqual((r as { skipped: string }).skipped, "replaced");
    assert.deepStrictEqual(checks, [{ identity: "refused", kernelPath: "not-reached" }]);
  });
});

// ===========================================================================
suite("opened-file checks — the realpath-to-identity gap: the kernel path closes it on Linux, and nothing else does (T5, T6)");

/**
 * The parent is swapped AFTER the reader's realpath and BEFORE its lstat, so
 * the identity captured is the OUTSIDE object's and the identity check passes.
 * Only the kernel's own record of the opened object refuses this. Where that
 * record is unavailable the outside bytes are read: that is the documented
 * residual on darwin and win32, and it is asserted as such rather than hidden.
 */
function realpathGapCase(lab: Lab, linkTo: string, what: string): void {
  const { checks, hooks } = collect();
  const w = fireAfter("realpathSync", (a) => String(a) === lab.target, () => swapParent(lab, linkTo));
  const r = withWraps([w], () => readTextFileResult(lab.root, REL, cfg(), hooks));
  platformSkip(w.state, "replacing the parent directory");
  assertFired(w.state, what);
  if (KERNEL_PATH) {
    assert.strictEqual((r as { skipped: string }).skipped, "outside", `${what}: the kernel path must refuse the outside object`);
    assert.deepStrictEqual(checks, [{ identity: "verified", kernelPath: "refused" }]);
  } else {
    // RESIDUAL, measured and documented: without a kernel path the one-syscall
    // gap is crossed and the outside object's bytes are read.
    assert.strictEqual((r as { text: string }).text, OUTSIDE, `${what}: expected the documented residual on ${process.platform}`);
    assert.deepStrictEqual(checks, [{ identity: "verified", kernelPath: "unavailable" }]);
    console.log(`    RESIDUAL on ${process.platform}: ${what} crossed the realpath-to-identity gap (no kernel path); outside bytes were read`);
  }
}

test("T6 A2: a parent swap in the realpath-to-lstat gap is refused by the kernel path on Linux; recorded as the residual elsewhere", () => {
  withLab((lab) => realpathGapCase(lab, lab.outside, "A2"));
});

test("T5 B1: the sibling-prefix trap `<root>2` is refused on Linux -- by component boundary, never by string prefix", () => {
  withLab((lab) => {
    const trap = lab.root + "2";
    fs.mkdirSync(trap);
    fs.writeFileSync(path.join(trap, "t.txt"), OUTSIDE);
    realpathGapCase(lab, trap, "B1");
  });
});

test("kernelPathInside is a component-boundary test on raw bytes: trap refused, deleted suffix kept, root itself accepted", () => {
  const root = "/lab/root";
  const inside = (s: string) => kernelPathInside(Buffer.from(s), root);
  assert.strictEqual(inside("/lab/root/sub/t.txt"), true);
  assert.strictEqual(inside("/lab/root"), true, "the root itself");
  assert.strictEqual(inside("/lab/root2/t.txt"), false, "the sibling-prefix trap");
  assert.strictEqual(inside("/lab/root2"), false);
  assert.strictEqual(inside("/lab/roo"), false);
  assert.strictEqual(inside("/lab/root/sub/t.txt (deleted)"), true, "an unlinked inside file keeps its raw suffix and stays inside");
  assert.strictEqual(inside("/lab/outside/t.txt (deleted)"), false, "the suffix is never stripped to manufacture anything");
  assert.strictEqual(inside("/lab/root/"), false, "a bare trailing slash is not a file under the root");
  assert.strictEqual(kernelPathInside(Buffer.from("/etc/passwd"), "/"), true, "a root of `/` does not demand `//`");
  assert.strictEqual(kernelPathInside(Buffer.from("/lab/root/x"), "/lab/root/"), true, "a root spelled with a trailing slash");
  assert.strictEqual(kernelPathInside(Buffer.from("/lab/rootx"), "/lab/root/"), false);
});

// ===========================================================================
suite("opened-file checks — movement and deletion after the open (T7, T8)");

test("T7 M2: a parent moved out of the root after the open and before the kernel-path check is refused on Linux", () => {
  withLab((lab) => {
    const { checks, hooks } = collect();
    // fstat is the reader's first call on the new descriptor; the move lands
    // after it and before the kernel-path read.
    const w = fireAfter("fstatSync", () => true, () => fs.renameSync(path.join(lab.root, "sub"), path.join(lab.outside, "sub.moved")));
    const r = withWraps([w], () => readTextFileResult(lab.root, REL, cfg(), hooks));
    platformSkip(w.state, "moving the parent of an open file");
    assertFired(w.state, "M2");
    if (KERNEL_PATH) {
      assert.strictEqual((r as { skipped: string }).skipped, "outside");
      assert.deepStrictEqual(checks, [{ identity: "verified", kernelPath: "refused" }]);
    } else {
      // The object IS the inspected inside file; without a kernel path its
      // movement is not observed and it is read. Inside content, so the
      // residual here is a location claim, not an outside read.
      assert.strictEqual((r as { text: string }).text, INSIDE);
      assert.deepStrictEqual(checks, [{ identity: "verified", kernelPath: "unavailable" }]);
    }
  });
});

test("T8 D1: a file unlinked after the open is still read; on Linux its raw `(deleted)` kernel path is accepted without stripping", () => {
  withLab((lab) => {
    const { checks, hooks } = collect();
    const w = fireAfter("fstatSync", () => true, () => fs.unlinkSync(lab.target));
    const r = withWraps([w], () => readTextFileResult(lab.root, REL, cfg(), hooks));
    platformSkip(w.state, "unlinking an open file");
    assertFired(w.state, "D1");
    assert.strictEqual((r as { text: string }).text, INSIDE);
    assert.deepStrictEqual(checks, [{ identity: "verified", kernelPath: KP_EXPECTED }]);
  });
});

// ===========================================================================
suite("opened-file checks — capability absent versus evidence failed (T9, T10)");

function linuxOnly(): void {
  if (!KERNEL_PATH) skip("the kernel-path check is attempted only on linux with /proc/self/fd; this host has none to simulate");
}

test("T9a: with no readable /proc/self/fd at all the read continues and the descriptor records kernel path unavailable", () => {
  linuxOnly();
  withLab((lab) => {
    const { checks, hooks } = collect();
    const realReadlink = fs.readlinkSync;
    const realStat = fs.statSync;
    let sawLink = false;
    let sawProbe = false;
    (fs as any).readlinkSync = function (this: unknown, p: unknown, ...rest: unknown[]) {
      if (String(p).startsWith("/proc/self/fd/")) { sawLink = true; throw Object.assign(new Error("ENOENT"), { code: "ENOENT" }); }
      return (realReadlink as any).apply(this, [p, ...rest]);
    };
    (fs as any).statSync = function (this: unknown, p: unknown, ...rest: unknown[]) {
      if (String(p) === "/proc/self/fd") { sawProbe = true; throw Object.assign(new Error("ENOENT"), { code: "ENOENT" }); }
      return (realStat as any).apply(this, [p, ...rest]);
    };
    let r;
    try {
      r = readTextFileResult(lab.root, REL, cfg(), hooks);
    } finally {
      (fs as any).readlinkSync = realReadlink;
      (fs as any).statSync = realStat;
    }
    assert.ok(sawLink && sawProbe, "the reader must try the link and then probe the directory");
    assert.strictEqual((r as { text: string }).text, INSIDE, "an absent capability continues the read");
    assert.deepStrictEqual(checks, [{ identity: "verified", kernelPath: "unavailable" }]);
  });
});

test("T9b: with /proc/self/fd present but THIS descriptor's link unreadable the file is refused and the descriptor records failed", () => {
  linuxOnly();
  withLab((lab) => {
    const { checks, hooks } = collect();
    const realReadlink = fs.readlinkSync;
    let saw = false;
    (fs as any).readlinkSync = function (this: unknown, p: unknown, ...rest: unknown[]) {
      if (String(p).startsWith("/proc/self/fd/")) { saw = true; throw Object.assign(new Error("EACCES"), { code: "EACCES" }); }
      return (realReadlink as any).apply(this, [p, ...rest]);
    };
    let r;
    try {
      r = readTextFileResult(lab.root, REL, cfg(), hooks);
    } finally {
      (fs as any).readlinkSync = realReadlink;
    }
    assert.ok(saw, "the link read did not happen");
    assert.strictEqual((r as { skipped: string }).skipped, "unreadable", "a failed attempt to obtain evidence refuses; it is not an absence");
    assert.deepStrictEqual(checks, [{ identity: "verified", kernelPath: "failed" }]);
  });
});

test("T10: an inspected object reporting no identity (dev 0, ino 0) is read with the identity check recorded unavailable", () => {
  withLab((lab) => {
    const { checks, hooks } = collect();
    const real = fs.lstatSync;
    let saw = false;
    (fs as any).lstatSync = function (this: unknown, p: unknown, ...rest: unknown[]) {
      const st = (real as any).apply(this, [p, ...rest]);
      if (String(p) === lab.target) {
        saw = true;
        // The real stats with the identity fields zeroed; every method survives.
        return Object.assign(Object.create(Object.getPrototypeOf(st)), st, { dev: 0n, ino: 0n });
      }
      return st;
    };
    let r;
    try {
      r = readTextFileResult(lab.root, REL, cfg(), hooks);
    } finally {
      (fs as any).lstatSync = real;
    }
    assert.ok(saw, "the identity capture did not happen on the target");
    assert.strictEqual((r as { text: string }).text, INSIDE);
    assert.deepStrictEqual(checks, [{ identity: "unavailable", kernelPath: KP_EXPECTED }]);
  });
});

test("a failed fstat on the open descriptor refuses as unreadable and records identity failed", () => {
  withLab((lab) => {
    const { checks, hooks } = collect();
    const real = fs.fstatSync;
    let saw = false;
    (fs as any).fstatSync = function () {
      saw = true;
      throw Object.assign(new Error("EIO"), { code: "EIO" });
    };
    let r;
    try {
      r = readTextFileResult(lab.root, REL, cfg(), hooks);
    } finally {
      (fs as any).fstatSync = real;
    }
    assert.ok(saw);
    assert.strictEqual((r as { skipped: string }).skipped, "unreadable");
    assert.deepStrictEqual(checks, [{ identity: "failed", kernelPath: "not-reached" }]);
  });
});

// ===========================================================================
suite("opened-file checks — the timing gap, asserted as the residual it is (T15, T16)");

/**
 * MI1 / MI2. The parent is swapped in the realpath-to-lstat gap, so the
 * identity captured is the OUTSIDE object's and the reader opens that object
 * through the replaced parent. After the open (MI1) or after the fstat (MI2),
 * and before the kernel-path check, the link is removed, the directory
 * recreated and THAT SAME OPEN OBJECT renamed to `<root>/sub/t.txt`. Both
 * checks then pass and the outside-origin bytes are read -- on every platform.
 * The check proves location at the CHECK, not at the open; nothing available to
 * this product prevents this (it needs openat2 RESOLVE_BENEATH). Recorded as
 * accepted by design; a test must not assert refusal here.
 */
function movedInCase(lab: Lab, second: "openSync" | "fstatSync", what: string): void {
  const { checks, hooks } = collect();
  const first = fireAfter("realpathSync", (a) => String(a) === lab.target, () => swapParent(lab, lab.outside));
  const moveIn = () => {
    fs.rmSync(path.join(lab.root, "sub"), { recursive: false, force: false });
    fs.mkdirSync(path.join(lab.root, "sub"));
    fs.renameSync(lab.outsideFile, lab.target);
  };
  const w2 = second === "openSync"
    ? fireAfter("openSync", (a) => String(a) === lab.target, moveIn)
    : fireAfter("fstatSync", () => true, moveIn);
  const r = withWraps([first, w2], () => readTextFileResult(lab.root, REL, cfg(), hooks));
  platformSkip(first.state, "replacing the parent directory");
  platformSkip(w2.state, "moving the open outside object under the root");
  assertFired(first.state, `${what} parent swap`);
  assertFired(w2.state, `${what} move-in`);
  assert.strictEqual((r as { text: string }).text, OUTSIDE, `${what}: accepted by design -- the object is under the root at the check`);
  assert.deepStrictEqual(checks, [{ identity: "verified", kernelPath: KP_EXPECTED }]);
  console.log(`    ${what} on ${process.platform}: ACCEPTED BY DESIGN (check-time containment); outside-origin bytes were read`);
}

test("T15 MI1: an outside object moved under the root after the open and before the checks is accepted, bytes read", () => {
  withLab((lab) => movedInCase(lab, "openSync", "MI1"));
});

test("T15 MI2: the same, moved in after the fstat and before the kernel-path check", () => {
  withLab((lab) => movedInCase(lab, "fstatSync", "MI2"));
});

test("T16 MO1: an inside object moved out after the checks and before the read is still read -- the reads are not re-validated", () => {
  withLab((lab) => {
    const { checks, hooks } = collect();
    let fired = false;
    let error: null | { call: string; code: string } = null;
    hooks.afterOpen = () => {
      fired = true;
      try {
        fs.renameSync(path.join(lab.root, "sub"), path.join(lab.outside, "sub.moved"));
      } catch (e) {
        error = { call: "renameSync", code: String((e as NodeJS.ErrnoException).code) };
        throw e;
      }
    };
    const r = readTextFileResult(lab.root, REL, cfg(), hooks);
    platformSkip({ error }, "moving the parent of an open file");
    assert.strictEqual(fired, true, "MO1: the seam did not fire");
    assert.strictEqual((r as { text: string }).text, INSIDE, "MO1: read by design; the object was inside at the check");
    assert.deepStrictEqual(checks, [{ identity: "verified", kernelPath: KP_EXPECTED }]);
    console.log(`    MO1 on ${process.platform}: READ BY DESIGN (the descriptor is not re-validated after the check)`);
  });
});

// ===========================================================================
suite("opened-file checks — the binary header probe is covered by the same checked descriptor (T17, T18)");

test("T17: a parent swap after the binary reader's lstat gate hands the header acceptor NO outside bytes", () => {
  // RED on the base build, measured (f1-containment-design-review-addendum-
  // timing): the probe opened on its own and passed 16 outside bytes to the
  // acceptor before any check could run. This is the case that rejects a
  // shared-bulk-reader-only implementation.
  withLab((lab) => {
    const { checks, hooks } = collect();
    const received: Buffer[] = [];
    const accepts = (head: Buffer) => { received.push(Buffer.from(head)); return true; };
    const w = fireAfter("lstatSync", (a) => String(a) === lab.target, () => swapParent(lab, lab.outside));
    const r = withWraps([w], () => readBinaryCandidate(lab.root, REL, cfg(), accepts, 16, hooks));
    platformSkip(w.state, "replacing the parent directory");
    assertFired(w.state, "T17");
    assert.strictEqual(received.length, 0, `the header acceptor received ${received.length} call(s) with ${received.map((b) => JSON.stringify(b.toString())).join(", ")}`);
    assert.strictEqual((r as { skipped: string }).skipped, "replaced");
    assert.deepStrictEqual(checks, [{ identity: "refused", kernelPath: "not-reached" }]);
  });
});

test("T18: the header probe and the bulk read come from ONE descriptor, checked once -- exactly one open per candidate", () => {
  // RED on the base build: two opens (probe, then bulk) and two records.
  withLab((lab) => {
    const { checks, hooks } = collect();
    let opens = 0;
    const real = fs.openSync;
    (fs as any).openSync = function (this: unknown, p: unknown, ...rest: unknown[]) {
      if (String(p) === lab.target) opens++;
      return (real as any).apply(this, [p, ...rest]);
    };
    let r;
    const heads: string[] = [];
    try {
      r = readBinaryCandidate(lab.root, REL, cfg(), (head, size) => { heads.push(`${head.toString()}|${size}`); return true; }, 6, hooks);
    } finally {
      (fs as any).openSync = real;
    }
    assert.strictEqual(opens, 1, `expected one open per candidate, saw ${opens}`);
    assert.strictEqual(checks.length, 1, "one descriptor, one record");
    assert.deepStrictEqual(heads, [`${INSIDE.slice(0, 6)}|${INSIDE.length}`], "the head is the first bytes of the checked object, with its fstat size");
    assert.strictEqual((r as { bytes: Buffer }).bytes.toString(), INSIDE, "the bulk read follows from the same descriptor");
  });
});

test("a declined header still reads nothing further and is still not counted as a refusal", () => {
  withLab((lab) => {
    const { checks, hooks } = collect();
    const r = readBinaryCandidate(lab.root, REL, cfg(), () => false, 16, hooks);
    assert.strictEqual((r as { skipped: string }).skipped, "not-a-file");
    assert.deepStrictEqual(checks, [{ identity: "verified", kernelPath: KP_EXPECTED }], "the descriptor was checked before the head was read");
  });
});

// ===========================================================================
suite("opened-file checks — win32 junction parent swap (T13)");

test("T13: a junction swapped in for the parent after the identity capture is refused on Windows", () => {
  if (process.platform !== "win32") skip("junctions exist only on Windows; the POSIX parent-swap cases above cover this host");
  withLab((lab) => {
    const { checks, hooks } = collect();
    const w = fireAfter("lstatSync", (a) => String(a) === lab.target, () => {
      fs.renameSync(path.join(lab.root, "sub"), path.join(lab.dir, "sub.moved"));
      fs.symlinkSync(lab.outside, path.join(lab.root, "sub"), "junction");
    });
    const r = withWraps([w], () => readTextFileResult(lab.root, REL, cfg(), hooks));
    platformSkip(w.state, "swapping a junction in for the parent");
    assertFired(w.state, "T13");
    assert.strictEqual((r as { skipped: string }).skipped, "replaced");
    assert.deepStrictEqual(checks, [{ identity: "refused", kernelPath: "not-reached" }]);
  });
});

// ===========================================================================
suite("opened-file checks — descriptor cleanup on every refusal (T12)");

test("no descriptor is leaked by an identity refusal, a kernel-path refusal, an evidence failure or a throw, and the lab can be removed", () => {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(tmpdir(), "secretloop-ofc-clean-")));
  try {
    const before = fdProbe(dir);
    for (let i = 0; i < 10; i++) {
      // Fresh fixtures per iteration, inside the one lab whose removal is asserted.
      const lab: Lab = {
        dir,
        root: path.join(dir, `r${i}`),
        outside: path.join(dir, `o${i}`),
        target: path.join(dir, `r${i}`, "sub", "t.txt"),
        outsideFile: path.join(dir, `o${i}`, "t.txt"),
      };
      fs.mkdirSync(path.join(lab.root, "sub"), { recursive: true });
      fs.mkdirSync(lab.outside);
      fs.writeFileSync(lab.target, INSIDE);
      fs.writeFileSync(lab.outsideFile, OUTSIDE);

      // Identity refusal (A1').
      const a = fireAfter("lstatSync", (x) => String(x) === lab.target, () => { fs.unlinkSync(lab.target); fs.symlinkSync(lab.outsideFile, lab.target); });
      const ra = withWraps([a], () => readTextFileResult(lab.root, REL, cfg()));
      platformSkip(a.state, "replacing the inspected name");
      assert.strictEqual((ra as { skipped: string }).skipped, "replaced");
      fs.unlinkSync(lab.target);
      fs.writeFileSync(lab.target, INSIDE);

      if (KERNEL_PATH) {
        // Kernel-path refusal (M2) and evidence failure (T9b).
        const m = fireAfter("fstatSync", () => true, () => fs.renameSync(path.join(lab.root, "sub"), path.join(lab.outside, "sub.moved")));
        const rm = withWraps([m], () => readTextFileResult(lab.root, REL, cfg()));
        assert.strictEqual((rm as { skipped: string }).skipped, "outside");
        fs.renameSync(path.join(lab.outside, "sub.moved"), path.join(lab.root, "sub"));
        const realReadlink = fs.readlinkSync;
        (fs as any).readlinkSync = function (this: unknown, p: unknown, ...rest: unknown[]) {
          if (String(p).startsWith("/proc/self/fd/")) throw Object.assign(new Error("EACCES"), { code: "EACCES" });
          return (realReadlink as any).apply(this, [p, ...rest]);
        };
        try {
          assert.strictEqual((readTextFileResult(lab.root, REL, cfg()) as { skipped: string }).skipped, "unreadable");
        } finally {
          (fs as any).readlinkSync = realReadlink;
        }
      }
      // A throw from the seam after the checks.
      assert.strictEqual((readTextFileResult(lab.root, REL, cfg(), () => { throw new Error("x"); }) as { skipped: string }).skipped, "unreadable");
      // The header probe refusing (T17 shape).
      const h = fireAfter("lstatSync", (x) => String(x) === lab.target, () => { fs.renameSync(path.join(lab.root, "sub"), path.join(dir, `moved${i}`)); fs.symlinkSync(lab.outside, path.join(lab.root, "sub"), process.platform === "win32" ? "junction" : "dir"); });
      const rh = withWraps([h], () => readBinaryCandidate(lab.root, REL, cfg(), () => true, 16));
      platformSkip(h.state, "replacing the parent directory");
      assert.strictEqual((rh as { skipped: string }).skipped, "replaced");
    }
    const after = fdProbe(dir);
    assert.strictEqual(after, before, `descriptor number drifted ${before} -> ${after}: a refusal leaked a handle`);
  } finally {
    // Not forced: on Windows a leaked handle is what makes this removal fail.
    let removed = true;
    let why = "";
    try {
      fs.rmSync(dir, { recursive: true });
    } catch (e) {
      removed = false;
      why = String((e as NodeJS.ErrnoException).code ?? e);
      fs.rmSync(dir, { recursive: true, force: true });
    }
    assert.ok(removed, `the lab could not be removed (${why}) on ${process.platform}; on Windows that is what a leaked descriptor looks like`);
  }
});

// ===========================================================================
suite("opened-file checks — the accounting and its disclosure (2c)");

test("records are counted per descriptor into five buckets per check, and a later verified record erases nothing", () => {
  const acc: OpenedFileChecks = emptyOpenedFileChecks();
  assert.deepStrictEqual(acc, {
    opened: 0,
    identity: { verified: 0, refused: 0, unavailable: 0, failed: 0, notReached: 0 },
    kernelPath: { verified: 0, refused: 0, unavailable: 0, failed: 0, notReached: 0 },
  });
  recordOpenedFileCheck(acc, { identity: "verified", kernelPath: "unavailable" });
  recordOpenedFileCheck(acc, { identity: "refused", kernelPath: "not-reached" });
  recordOpenedFileCheck(acc, { identity: "unavailable", kernelPath: "failed" });
  recordOpenedFileCheck(acc, { identity: "failed", kernelPath: "not-reached" });
  recordOpenedFileCheck(acc, { identity: "verified", kernelPath: "verified" });
  recordOpenedFileCheck(acc, { identity: "verified", kernelPath: "verified" });
  assert.strictEqual(acc.opened, 6);
  assert.deepStrictEqual(acc.identity, { verified: 3, refused: 1, unavailable: 1, failed: 1, notReached: 0 });
  assert.deepStrictEqual(acc.kernelPath, { verified: 2, refused: 0, unavailable: 1, failed: 1, notReached: 2 });
  for (const c of [acc.identity, acc.kernelPath]) {
    assert.strictEqual(c.verified + c.refused + c.unavailable + c.failed + c.notReached, acc.opened, "every descriptor has exactly one outcome per check");
  }
});

test("the clause lists every non-zero outcome, says zero as zero, and is the LAST clause -- in report.ts and mcp-core.ts alike", () => {
  const acc = emptyOpenedFileChecks();
  assert.strictEqual(describeOpenedFileChecks(acc), "0 descriptor(s) opened for content");
  recordOpenedFileCheck(acc, { identity: "verified", kernelPath: "unavailable" });
  recordOpenedFileCheck(acc, { identity: "verified", kernelPath: "unavailable" });
  recordOpenedFileCheck(acc, { identity: "refused", kernelPath: "not-reached" });
  assert.strictEqual(describeCheckCounts(acc.identity), "2 verified, 1 refused");
  assert.strictEqual(describeCheckCounts(acc.kernelPath), "2 unavailable, 1 not reached");
  assert.strictEqual(
    describeOpenedFileChecks(acc),
    "3 descriptor(s) opened for content: identity 2 verified, 1 refused; kernel path 2 unavailable, 1 not reached"
  );
  const notes = { unreadableExcluded: 1, replacedExcluded: 1, openedFileChecks: acc };
  const expected =
    "4 file(s); 1 file(s) not scanned — could not be read; 1 file(s) not scanned — replaced between inspection and read; " +
    "3 descriptor(s) opened for content: identity 2 verified, 1 refused; kernel path 2 unavailable, 1 not reached";
  assert.strictEqual(describeScope(4, "file", notes), expected);
  assert.strictEqual(mcpDescribeScope(4, "file", notes), expected, "the MCP copy must agree word for word");
  assert.strictEqual(describeScope(4, "file", {}), "4 file(s)", "no accounting supplied, no clause");
  assert.strictEqual(
    describeScope(0, "file", { openedFileChecks: emptyOpenedFileChecks() }),
    "0 file(s) — nothing was scanned, so this is not a clean result; 0 descriptor(s) opened for content"
  );
});

test("a refusal is a coverage limitation; an unavailable check is disclosed but is not one", () => {
  assert.deepStrictEqual(coverageLimitations({ replacedExcluded: 2 }), ["2 file(s) not scanned — replaced between inspection and read"]);
  assert.deepStrictEqual(coverageLimitations({ replacedExcluded: 0 }), []);
  // `unavailable` has no limitation input at all: the read happened under
  // the checks that were possible and the counts say which.
  assert.deepStrictEqual(coverageLimitations({}), []);
});

finish();
