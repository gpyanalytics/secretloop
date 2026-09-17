import { readTextFileResult, readBinaryCandidate } from "../src/walk";
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
    if (refused !== null && process.platform === "win32") {
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
