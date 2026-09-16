import { readTextFileResult, readBinaryCandidate } from "../src/walk";
import { defaultConfig } from "../src/config";
import { test, suite, finish, assert } from "./harness";
import {
  mkdtempSync,
  mkdirSync,
  rmSync,
  writeFileSync,
  symlinkSync,
  unlinkSync,
  openSync,
  closeSync,
} from "fs";
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
    const r = readTextFileResult(d, "orig.txt", cfg(CAP), () => {
      unlinkSync(f);
      symlinkSync(other, f);
    });
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

finish();
