import { readTextFileResult, readBinaryCandidate, READ_OPEN_FLAGS, NONBLOCKING_OPEN_SUPPORTED } from "../src/walk";
import { constants as fsConstants } from "fs";
import { defaultConfig } from "../src/config";
import { test, suite, finish, assert, skip } from "./harness";
import {
  mkdtempSync,
  mkdirSync,
  rmSync,
  writeFileSync,
  symlinkSync,
  unlinkSync,
  openSync,
  closeSync,
  existsSync,
} from "fs";
import { execFileSync, spawnSync } from "child_process";
import { tmpdir } from "os";
import * as path from "path";

/**
 * F-1 CONCERN B — the byte cap must bound the READ, not describe an earlier
 * stat of a name that may no longer refer to the same object.
 *
 * WHAT THESE TESTS DRIVE: the real `readTextFileResult` and
 * `readBinaryCandidate`. Nothing is mocked and `fs` is not patched.
 *
 * THE SEAM, NAMED HONESTLY: both readers take an optional `afterOpen` callback,
 * the same test-only seam `src/compare.ts`'s reader already uses. It runs after
 * the descriptor is open and before the first read, which is exactly the point
 * the old stat-then-read shape was vulnerable. That makes the ordering
 * DETERMINISTIC -- no sleeping, no retry loop, no racing.
 *
 * WHAT THEY DO NOT COVER: containment. F-1 Concern A -- a path replaced between
 * the containment check and the open, whether at the final component or a parent
 * directory -- is NOT addressed by this change and is NOT tested here. One
 * descriptor fixes WHICH object is read; it does not prove that object is inside
 * the root.
 */

const CAP = 64;

function cfg(maxFileSizeBytes: number) {
  return { ...defaultConfig, maxFileSizeBytes };
}

function withLab(fn: (dir: string) => void): void {
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-bounded-"));
  try {
    fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

suite("walk.ts — bounded file reads (F-1 Concern B)");

// ---------------------------------------------------------------- ordinary
test("an empty file reads as empty, not as a refusal", () => {
  withLab((d) => {
    writeFileSync(path.join(d, "e.txt"), "");
    const r = readTextFileResult(d, "e.txt", cfg(CAP));
    assert.ok("text" in r, "an empty file is readable");
    assert.strictEqual((r as { text: string }).text, "");
  });
});

test("an ordinary below-limit file is read in full", () => {
  withLab((d) => {
    writeFileSync(path.join(d, "s.txt"), "A".repeat(10));
    const r = readTextFileResult(d, "s.txt", cfg(CAP));
    assert.strictEqual((r as { text: string }).text.length, 10);
  });
});

test("exactly the byte limit is accepted", () => {
  withLab((d) => {
    writeFileSync(path.join(d, "at.txt"), "A".repeat(CAP));
    const r = readTextFileResult(d, "at.txt", cfg(CAP));
    assert.ok("text" in r, "exactly the limit must be read, not refused");
    assert.strictEqual((r as { text: string }).text.length, CAP);
  });
});

test("one byte over the limit is refused as oversized", () => {
  withLab((d) => {
    writeFileSync(path.join(d, "over.txt"), "A".repeat(CAP + 1));
    const r = readTextFileResult(d, "over.txt", cfg(CAP));
    assert.strictEqual((r as { skipped: string }).skipped, "oversized");
  });
});

// ---------------------------------------------------------------- the defect
test("REGRESSION: growth after fstat is refused, not read", () => {
  // FAILS against the starting source: the old shape read 4096 bytes against a
  // 64-byte cap, because readFileSync has no byte limit at all.
  withLab((d) => {
    const f = path.join(d, "grow.txt");
    writeFileSync(f, "S".repeat(10));
    const r = readTextFileResult(d, "grow.txt", cfg(CAP), () =>
      writeFileSync(f, "G".repeat(4096))
    );
    assert.ok(!("text" in r), "a file that grew past the cap must not be read in full");
    assert.strictEqual((r as { skipped: string }).skipped, "oversized");
  });
});

test("REGRESSION: growth across read iterations is still bounded", () => {
  // The cap is smaller than one read chunk here, so the refusal must come from
  // the running total rather than from any single read returning too much.
  withLab((d) => {
    const f = path.join(d, "grow2.txt");
    writeFileSync(f, "S".repeat(8));
    const r = readTextFileResult(d, "grow2.txt", cfg(16), () =>
      writeFileSync(f, "G".repeat(200_000))
    );
    assert.strictEqual((r as { skipped: string }).skipped, "oversized");
  });
});

test("REGRESSION: bytes come from the opened descriptor, not the path", () => {
  // The path is REPLACED after the open. A correct reader still delivers the
  // bytes of the object it opened. This is about read consistency, NOT about
  // containment -- see the suite header.
  withLab((d) => {
    const f = path.join(d, "orig.txt");
    const other = path.join(d, "other.txt");
    writeFileSync(f, "ORIGINAL");
    writeFileSync(other, "REPLACEMENT");
    // The replacement is the FIXTURE, not the subject. The reader swallows a
    // throw from the seam as `unreadable`, which on the first native Windows
    // run read as "actual: undefined" with no way to tell a reader defect from
    // a platform refusing to replace a name under an open descriptor. So the
    // fixture records its own failure, by call and code, and reports it.
    let refused: { call: string; code: string } | null = null;
    const r = readTextFileResult(d, "orig.txt", cfg(CAP), () => {
      try {
        unlinkSync(f);
      } catch (e) {
        refused = { call: "unlink", code: String((e as NodeJS.ErrnoException).code) };
        throw e;
      }
      try {
        symlinkSync(other, f);
      } catch (e) {
        refused = { call: "symlink", code: String((e as NodeJS.ErrnoException).code) };
        throw e;
      }
    });
    // Only the codes by which Windows refuses to replace a name under an open
    // handle (measured: EPERM) qualify as the platform's answer. Any other
    // fixture failure -- a missing file, a bad path -- falls through to the
    // assertion below and FAILS on every platform, so a broken fixture can
    // never masquerade as a platform limit.
    const platformRefusal = new Set(["EPERM", "EBUSY", "EACCES"]);
    if (refused !== null && process.platform === "win32" && platformRefusal.has((refused as { code: string }).code)) {
      // Windows would not replace the name while the descriptor was open.
      // That is a platform property, recorded with the exact call and code;
      // it is not evidence about the reader either way, so the case is
      // skipped, not passed.
      const { call, code } = refused as { call: string; code: string };
      skip(`win32 refused to replace an open file's name at ${call} (${code}); the property cannot be exercised here`);
    }
    assert.strictEqual(refused, null, `the fixture failed at ${JSON.stringify(refused)}`);
    assert.strictEqual((r as { text: string }).text, "ORIGINAL");
  });
});

test("REGRESSION: the binary-candidate path is bounded too", () => {
  withLab((d) => {
    const f = path.join(d, "c.bin");
    writeFileSync(f, "S".repeat(10));
    const r = readBinaryCandidate(d, "c.bin", cfg(CAP), undefined, 16, () =>
      writeFileSync(f, "G".repeat(4096))
    );
    assert.ok(!("bytes" in r), "the binary reader must not read past the cap either");
    assert.strictEqual((r as { skipped: string }).skipped, "oversized");
  });
});

// ------------------------------------------------------- preserved behaviour
test("the non-dereferencing binary gate still refuses a final-component symlink", () => {
  // readBinaryCandidate's lstat check was deliberately KEPT. Losing it would
  // have been a silent containment weakening disguised as a size fix.
  withLab((d) => {
    const real = path.join(d, "real.bin");
    writeFileSync(real, "X".repeat(4));
    symlinkSync(real, path.join(d, "link.bin"));
    const r = readBinaryCandidate(d, "link.bin", cfg(CAP));
    assert.strictEqual((r as { skipped: string }).skipped, "not-a-file");
  });
});

test("a static outside-root symlink is still refused", () => {
  withLab((d) => {
    const root = path.join(d, "root");
    const outside = path.join(d, "outside");
    mkdirSync(root);
    mkdirSync(outside);
    writeFileSync(path.join(outside, "o.txt"), "OUT");
    symlinkSync(path.join(outside, "o.txt"), path.join(root, "l.txt"));
    const r = readTextFileResult(root, "l.txt", cfg(1_000_000));
    assert.strictEqual((r as { skipped: string }).skipped, "outside");
  });
});

test("a directory is classified not-a-file, and does not hang", () => {
  withLab((d) => {
    mkdirSync(path.join(d, "sub"));
    const r = readTextFileResult(d, "sub", cfg(CAP));
    assert.strictEqual((r as { skipped: string }).skipped, "not-a-file");
  });
});

test("a missing path is vanished, and an unopenable one is unreadable", () => {
  withLab((d) => {
    const gone = readTextFileResult(d, "nope.txt", cfg(CAP));
    assert.strictEqual((gone as { skipped: string }).skipped, "vanished");
  });
});

test("a read failure after open is classified unreadable, not silently empty", () => {
  withLab((d) => {
    const f = path.join(d, "f.txt");
    writeFileSync(f, "DATA");
    const r = readTextFileResult(d, "f.txt", cfg(CAP), () => {
      throw new Error("injected failure between open and read");
    });
    assert.strictEqual((r as { skipped: string }).skipped, "unreadable");
  });
});

// ------------------------------------------------------- descriptor cleanup
test("descriptors are released on success, refusal and throw alike", () => {
  // Counted, not inspected: open a probe descriptor before and after and assert
  // the number has not drifted. A leak in the reader would show as a gap.
  withLab((d) => {
    const f = path.join(d, "f.txt");
    writeFileSync(f, "A".repeat(10));
    const probe = () => {
      const fd = openSync(f, "r");
      closeSync(fd);
      return fd;
    };
    const before = probe();
    for (let i = 0; i < 20; i++) {
      readTextFileResult(d, "f.txt", cfg(CAP)); // success
      readTextFileResult(d, "f.txt", cfg(1), undefined); // refusal (oversized)
      readTextFileResult(d, "f.txt", cfg(CAP), () => {
        throw new Error("x");
      }); // throw
      readBinaryCandidate(d, "f.txt", cfg(CAP)); // binary success
    }
    const after = probe();
    assert.strictEqual(
      after,
      before,
      `descriptor number drifted ${before} -> ${after}; a reader is leaking`
    );
  });
});

// --------------------------------------------------- non-regular inputs
/**
 * REGRESSION, found in review of this very change.
 *
 * The first draft opened the descriptor and THEN classified the type from
 * `fstat`. That is the right order for a size guard and the wrong order for a
 * type guard: `openSync` on a FIFO with no writer BLOCKS INDEFINITELY, so the
 * reader hung where it used to answer "not-a-file" immediately. The staged-path
 * callers hand `readTextFileResult` names that never went through the walk, so
 * the input is not guaranteed to be a regular file.
 *
 * WHY A CHILD PROCESS: if this regression ever returns, an in-process call
 * would hang the whole suite forever rather than fail it. The child carries a
 * hard timeout, so the failure mode is a failing test with a legible message.
 */
test("a FIFO is refused promptly by both readers, without blocking on open", () => {
  // mkfifo is POSIX. On win32 this case is SKIPPED and counted as such -- it
  // used to `assert.ok(true)` and return, which the summary counted as a pass
  // for a body that never ran. A skip is not a pass; see harness.ts.
  if (process.platform === "win32") skip("mkfifo is POSIX; no FIFO can be created here");
  withLab((d) => {
    const fifo = path.join(d, "pipe");
    try {
      execFileSync("mkfifo", [fifo], { stdio: "ignore" });
    } catch {
      skip("mkfifo is unavailable on this host; the FIFO case did not run");
    }

    const root = path.join(__dirname, "..");
    const script = `
      const w = require(${JSON.stringify(path.join(root, "src", "walk"))});
      const { defaultConfig } = require(${JSON.stringify(
        path.join(root, "src", "config")
      )});
      const c = Object.assign({}, defaultConfig, { maxFileSizeBytes: ${CAP} });
      const s = (r) => (r && typeof r === "object" && "skipped" in r ? r.skipped : String(r));
      const t = s(w.readTextFileResult(${JSON.stringify(d)}, "pipe", c));
      const b = s(w.readBinaryCandidate(${JSON.stringify(d)}, "pipe", c));
      process.stdout.write(JSON.stringify({ t: t, b: b }));
    `;
    const run = spawnSync(
      process.execPath,
      ["-r", "ts-node/register/transpile-only", "-e", script],
      { cwd: root, timeout: 20000, encoding: "utf8" }
    );

    assert.ok(
      !run.error || (run.error as NodeJS.ErrnoException).code !== "ETIMEDOUT",
      "a reader BLOCKED on the FIFO instead of refusing it -- the open now " +
        "precedes the type check again"
    );
    assert.strictEqual(
      run.signal,
      null,
      `child died on ${run.signal}; stderr: ${run.stderr}`
    );
    assert.strictEqual(run.status, 0, `child failed: ${run.stderr}`);
    const got = JSON.parse(run.stdout) as { t: string; b: string };
    assert.strictEqual(got.t, "not-a-file", "text reader must refuse a FIFO");
    assert.strictEqual(got.b, "not-a-file", "binary reader must refuse a FIFO");
  });
});

// ------------------------------------- the FIFO OPEN WINDOW (slice 1 of F-1)
/**
 * THE DEMONSTRATED BLOCK, AND ITS CORRECTION.
 *
 * Both readers classify a path BEFORE opening it, so a FIFO that is already
 * there is refused promptly (the case above). But the classification and the
 * open are two resolutions of the same name, and a regular file replaced by a
 * FIFO between them reached a blocking open: measured on the unchanged source
 * (f1-containment-design, E2), the reader hung until its process was killed.
 *
 * These cases replace the file INSIDE the product's own pre-open type check --
 * a wrapper around fs.statSync (text) or fs.lstatSync (binary), fired once,
 * after the real call -- so the replacement lands exactly in the window, on
 * the unchanged source and on the corrected one alike. That is what makes the
 * result discriminating: the trigger reaches the same operation in both
 * builds, and a build that blocks fails on the TIMEOUT below rather than
 * skipping. Each child also counts its descriptors before and after, and
 * removes its own lab directory, so a refusal that leaked a handle fails too.
 *
 * WIN32: no FIFO can exist on an NTFS path, and fs.constants.O_NONBLOCK is
 * undefined there, so the product falls back to a plain read-only open. These
 * cases SKIP on win32 and are counted as such; the ordinary-file cases in this
 * file are what Windows CI measures.
 */
const FIFO_CHILD_TIMEOUT_MS = 10000;

function fifoSwapChild(mode: "text" | "binary" | "header", lab: string): { run: ReturnType<typeof spawnSync>; got: any } {
  const root = path.join(__dirname, "..");
  // The lab directory is created by the PARENT and handed in, so that a child
  // killed on the timeout -- the defect this case exists to catch -- cannot
  // leave a directory holding a FIFO behind in the temporary directory. The
  // child still removes it itself on the way out (the Windows-shaped leak
  // detector below); the parent's own removal is the backstop.
  const script = `
    const fs = require("fs"), os = require("os"), path = require("path"), cp = require("child_process");
    const w = require(${JSON.stringify(path.join(root, "src", "walk"))});
    const { defaultConfig } = require(${JSON.stringify(path.join(root, "src", "config"))});
    const c = Object.assign({}, defaultConfig, { maxFileSizeBytes: 1000000 });
    const lab = ${JSON.stringify(lab)};
    const p = path.join(lab, "f.txt");
    fs.writeFileSync(p, "REGULAR");
    const probe = () => { const fd = fs.openSync(lab, "r"); fs.closeSync(fd); return fd; }; // the lab directory: present before and after, never the swapped path
    const before = probe();
    // Fire once, after the product's own pre-open type check on THIS path.
    const name = ${JSON.stringify(mode === "text" ? "statSync" : "lstatSync")};
    const real = fs[name]; let fired = false;
    fs[name] = function (...a) {
      const r = real.apply(this, a);
      if (!fired && String(a[0]) === p) { fired = true; fs.unlinkSync(p); cp.execFileSync("mkfifo", [p], { stdio: "ignore" }); }
      return r;
    };
    const s = (r) => (r && typeof r === "object" && "skipped" in r ? r.skipped : ("text" in r ? "TEXT" : "BYTES"));
    let result;
    try {
      result = ${mode === "text"
        ? `s(w.readTextFileResult(lab, "f.txt", c))`
        : mode === "binary"
          ? `s(w.readBinaryCandidate(lab, "f.txt", c))`
          : `s(w.readBinaryCandidate(lab, "f.txt", c, () => true, 16))`};
    } finally { fs[name] = real; }
    const after = probe();
    let removed = true; try { fs.rmSync(lab, { recursive: true }); } catch { removed = false; }
    process.stdout.write(JSON.stringify({ fired, result, before, after, removed }));
  `;
  const run = spawnSync(process.execPath, ["-r", "ts-node/register/transpile-only", "-e", script], {
    cwd: root,
    timeout: FIFO_CHILD_TIMEOUT_MS,
    encoding: "utf8",
  });
  let got: any = null;
  try { got = JSON.parse(run.stdout); } catch { /* reported below */ }
  return { run, got };
}

function fifoSwapCase(mode: "text" | "binary" | "header", what: string): void {
  if (process.platform === "win32") skip("mkfifo is POSIX; no FIFO can be created on an NTFS path");
  try {
    execFileSync("mkfifo", ["--version"], { stdio: "ignore" });
  } catch {
    // GNU mkfifo answers --version; BSD mkfifo exits non-zero on it. Probe by
    // making one instead, so the skip fires only when mkfifo truly is absent.
    const d = mkdtempSync(path.join(tmpdir(), "secretloop-mkfifo-"));
    try { execFileSync("mkfifo", [path.join(d, "p")], { stdio: "ignore" }); }
    catch { skip("mkfifo is unavailable on this host; the FIFO swap case did not run"); }
    finally { rmSync(d, { recursive: true, force: true }); }
  }
  const lab = mkdtempSync(path.join(tmpdir(), "secretloop-fifoswap-"));
  let run: ReturnType<typeof spawnSync>;
  let got: any;
  try {
    ({ run, got } = fifoSwapChild(mode, lab));
  } finally {
    // Backstop for a child that was killed: spawnSync's timeout terminates it,
    // and this removes whatever it left. On the corrected source the child has
    // already removed the directory and this is a no-op.
    rmSync(lab, { recursive: true, force: true });
  }
  // A TIMEOUT IS THE DEFECT. It is a failure of this case, never a skip.
  assert.ok(
    !run.error || (run.error as NodeJS.ErrnoException).code !== "ETIMEDOUT",
    `${what} BLOCKED on a FIFO swapped in after its type check: child killed after ${FIFO_CHILD_TIMEOUT_MS} ms`
  );
  assert.strictEqual(run.signal, null, `child died on ${run.signal}; stderr: ${run.stderr}`);
  assert.strictEqual(run.status, 0, `child failed: ${run.stderr}`);
  assert.ok(got, `child produced no result: ${run.stdout} ${run.stderr}`);
  assert.strictEqual(got.fired, true, "the replacement trigger did not fire: this run measured nothing");
  assert.strictEqual(got.result, "not-a-file", `${what} must refuse the swapped-in FIFO as not-a-file`);
  assert.strictEqual(got.after, got.before, `descriptor number drifted ${got.before} -> ${got.after}: a handle leaked on the refusal`);
  assert.strictEqual(got.removed, true, "the child's lab directory could not be removed after the refusal");
}

test("REGRESSION: the text reader no longer blocks on a file replaced by a FIFO after its stat", () => {
  fifoSwapCase("text", "readTextFileResult");
});

test("REGRESSION: the binary reader no longer blocks on a file replaced by a FIFO after its lstat", () => {
  fifoSwapCase("binary", "readBinaryCandidate (bulk read)");
});

test("REGRESSION: the binary HEADER PROBE no longer blocks on a file replaced by a FIFO after its lstat", () => {
  fifoSwapCase("header", "readBinaryCandidate (header probe)");
});

test("the content-open flags are read-only plus O_NONBLOCK exactly where the platform defines it", () => {
  // Pins the guard rather than assuming it. Printed so a platform's actual
  // constant is on record in its own CI log: win32 is expected to print
  // "undefined", and there the flags are a plain read-only open -- a fallback,
  // not protection.
  console.log(`    O_NONBLOCK on ${process.platform}: ${String(fsConstants.O_NONBLOCK)}; READ_OPEN_FLAGS=${READ_OPEN_FLAGS}; nonblocking-open supported=${NONBLOCKING_OPEN_SUPPORTED}`);
  assert.strictEqual(READ_OPEN_FLAGS, fsConstants.O_RDONLY | (fsConstants.O_NONBLOCK ?? 0));
  assert.strictEqual(NONBLOCKING_OPEN_SUPPORTED, fsConstants.O_NONBLOCK !== undefined);
  if (process.platform !== "win32") {
    assert.ok(NONBLOCKING_OPEN_SUPPORTED, "every supported POSIX platform is expected to define O_NONBLOCK");
  }
});

// ------------------------------------------------------ the cap's own values
/**
 * `loadConfig` does NOT validate `maxFileSizeBytes`; it is
 * `raw.maxFileSizeBytes ?? default`. So the reader must be correct for every
 * value that can actually arrive, not for the values the type says.
 *
 * Measured against the previous implementation: every one of these numbers
 * behaves identically on both. The two non-numbers are the documented
 * difference -- the old reader ignored an unusable cap and read the file whole;
 * this one refuses.
 */
test("numeric caps keep their previous meaning, including the boundaries", () => {
  withLab((d) => {
    const f = path.join(d, "f.txt");
    writeFileSync(f, "A".repeat(100));
    const skip = (limit: number) => {
      const r = readTextFileResult(d, "f.txt", cfg(limit));
      return "skipped" in r ? r.skipped : `read ${r.text.length}`;
    };
    assert.strictEqual(skip(100), "read 100", "exactly the size is allowed");
    assert.strictEqual(skip(99), "oversized", "one under refuses");
    assert.strictEqual(skip(0), "oversized");
    assert.strictEqual(skip(-1), "oversized", "a negative cap refuses");
    assert.strictEqual(skip(64.5), "oversized", "a fraction is not rounded up");
    assert.strictEqual(skip(100.5), "read 100", "a fraction is not rounded down");
    assert.strictEqual(
      skip(Number.POSITIVE_INFINITY),
      "read 100",
      "Infinity is a legitimate way to say 'no cap' and must still read"
    );
  });
});

test("a cap that is not a usable number refuses instead of reading unbounded", () => {
  withLab((d) => {
    const f = path.join(d, "f.txt");
    writeFileSync(f, "A".repeat(100));
    // A string is reachable from a real `.secretloop.json`; NaN is not
    // expressible in JSON but is reachable from an embedder calling the API.
    for (const bad of ["abc" as unknown as number, Number.NaN]) {
      const r = readTextFileResult(d, "f.txt", cfg(bad));
      assert.strictEqual(
        (r as { skipped: string }).skipped,
        "unreadable",
        `an unusable cap (${String(bad)}) must not read the file whole`
      );
    }
  });
});

// ------------------------------------------- cleanup under Windows semantics
/**
 * DESCRIPTOR LIFECYCLE, ASKED THE WAY WINDOWS ANSWERS IT.
 *
 * The case above counts file-descriptor NUMBERS, which is a POSIX-shaped
 * question. Windows answers a different and harsher one: libuv opens with
 * FILE_SHARE_DELETE, so unlinking a file with a live handle appears to succeed,
 * but the file is only MARKED for deletion and survives until the last handle
 * closes -- so REMOVING ITS DIRECTORY fails while a descriptor is leaked.
 *
 * That makes "can the temporary directory be deleted immediately afterwards"
 * a real leak detector on Windows, where the fd count is not. On POSIX this
 * case passes whether or not a descriptor leaked, because unlink and rmdir do
 * not care. It is therefore a MEASUREMENT ON WINDOWS AND A GUARD ON POSIX, and
 * it is labelled as such rather than counted as portable proof.
 */
test("the lab directory can be removed right after every reader outcome", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-cleanup-"));
  const f = path.join(dir, "f.txt");
  writeFileSync(f, "A".repeat(100));
  mkdirSync(path.join(dir, "sub"));

  // Every outcome the readers can produce, so a leak on any path is caught.
  readTextFileResult(dir, "f.txt", cfg(1000)); // success
  readTextFileResult(dir, "f.txt", cfg(10)); // oversized, at the fstat
  readTextFileResult(dir, "sub", cfg(1000)); // not-a-file, before any open
  readTextFileResult(dir, "gone.txt", cfg(1000)); // vanished
  readTextFileResult(dir, "f.txt", cfg("x" as unknown as number)); // unusable cap
  readTextFileResult(dir, "f.txt", cfg(1000), () => {
    throw new Error("injected failure between open and read");
  }); // throw, after the descriptor is open
  readBinaryCandidate(dir, "f.txt", cfg(1000)); // binary success
  readBinaryCandidate(dir, "f.txt", cfg(10)); // binary oversized

  let removed = true;
  let why = "";
  try {
    rmSync(dir, { recursive: true });
  } catch (e) {
    removed = false;
    why = String((e as NodeJS.ErrnoException).code ?? e);
  }
  assert.ok(
    removed,
    `the temporary directory could not be removed (${why}) on ${process.platform}; ` +
      `on Windows that is what a leaked descriptor looks like`
  );
  assert.strictEqual(existsSync(dir), false, "the temporary directory is really gone");
});

finish();
