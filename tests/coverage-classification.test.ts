import { test, suite, finish, assert } from "./harness";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, chmodSync, symlinkSync } from "fs";
import { tmpdir } from "os";
import { spawnSync } from "child_process";
import * as path from "path";
import { scanFiles } from "../src/workspace";
import { readTextFileResult } from "../src/walk";
import { mergeConfig } from "../src/config";
import { describeScope } from "../src/report";
import {
  coverageLimitations,
  REPORT_SCHEMA_VERSION,
} from "../src/report-metadata";
import { positiveSamples } from "./fixtures";
import { buildZip } from "./archive-builders";

/**
 * INTENTIONAL EXCLUSION IS NOT INABILITY TO INSPECT.
 *
 * `SkipReason` carried one bucket, `unreadable`, for four unrelated events: a
 * confirmed binary file, a path that was not a regular file, a path that had
 * gone away, and a read that threw. Its own disclosure said "binary or
 * unreadable" because it genuinely could not tell which had happened.
 *
 * `incomplete` is derived from the limitation list, and comparison requires
 * `incomplete: false` on BOTH sides. So one PNG anywhere in a tree made every
 * report from that tree permanently ineligible for comparison — for a scope
 * decision rather than a failure to look.
 *
 * These tests pin the split, and pin the three things it must NOT do: stop
 * disclosing binary skips, stop treating real failures as limitations, or let a
 * version-2 report and a version-3 report compare across the changed meaning.
 */

const CLI = path.join(__dirname, "..", "out", "cli.js");
const TOKEN = positiveSamples["github-token"];

const cli = (args: string[], dir: string) =>
  spawnSync("node", [CLI, ...args, "--path", dir], { encoding: "utf8" });

function withDir(fn: (dir: string) => void): void {
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-cov-"));
  try {
    fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const json = (dir: string, args: string[] = []) =>
  JSON.parse(cli(["scan", "--format", "json", ...args], dir).stdout);

/** A NUL byte in the first block: the binary heuristic, positively determined. */
function writeBinary(dir: string, name: string): void {
  writeFileSync(path.join(dir, name), Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0x00, 0x1a]));
}

/**
 * A DER object the PKCS#12 header prefilter ADMITS — outer SEQUENCE whose
 * declared extent is exactly the file — but which carries no plaintext key bag.
 *
 * The detector cannot tell "well-formed keystore, nothing in it" from "declined
 * by the structural walk", so this stands for a SUPPORTED binary format whose
 * inspection was inconclusive. Built by hand rather than with permission bits:
 * it behaves identically for every user, privileged or not.
 */
function writeAdmittedDer(dir: string, name: string): void {
  const body = Buffer.alloc(100);
  const header = Buffer.from([0x30, 0x82, (body.length >> 8) & 0xff, body.length & 0xff]);
  writeFileSync(path.join(dir, name), Buffer.concat([header, body]));
}

// ---------------------------------------------------------------------------
suite("coverage classification — a decision is not a failure");

test("text plus an intentionally excluded binary: disclosed, scanned, and COMPLETE", () => {
  withDir((dir) => {
    writeFileSync(path.join(dir, "app.js"), "const ok = 1;\n");
    writeBinary(dir, "logo.png");
    const d = json(dir);

    assert.strictEqual(d.summary.scannedCount, 1, "the text file must still be scanned");
    // The point of the change.
    assert.strictEqual(d.incomplete, false, "a PNG must not make the report incomplete");
    assert.deepStrictEqual(d.summary.coverage.limitations, [], "binary is not a limitation");
    // And the point it must NOT cost: the skip is still disclosed.
    assert.match(
      d.summary.scope,
      /1 file\(s\) not scanned — binary/,
      `the binary skip went silent: ${d.summary.scope}`
    );
    assert.ok(
      !/binary or unreadable/.test(d.summary.scope),
      "the conflated wording must be gone"
    );
  });
});

test("a genuine read failure still makes the report incomplete", () => {
  withDir((dir) => {
    writeFileSync(path.join(dir, "app.js"), "const ok = 1;\n");
    // A supported binary format whose inspection was inconclusive. No chmod, so
    // this holds under a privileged user too.
    writeAdmittedDer(dir, "store.p12");
    const d = json(dir);

    assert.strictEqual(d.incomplete, true, "an inconclusive supported-format read must be a limitation");
    assert.deepStrictEqual(d.summary.coverage.limitations, [
      "1 file(s) not scanned — could not be read",
    ]);
    assert.ok(
      !/not scanned — binary/.test(d.summary.scope),
      `a failed keystore inspection must not be written off as binary: ${d.summary.scope}`
    );
  });
});

test("permission failure is a limitation — skipped when the user can read anything", () => {
  withDir((dir) => {
    writeFileSync(path.join(dir, "app.js"), "const ok = 1;\n");
    const secret = path.join(dir, "locked.txt");
    writeFileSync(secret, `const t = "${TOKEN}";\n`);
    chmodSync(secret, 0o000);
    // chmod is advisory for root, which would read the file and make this a
    // false green. The controlled fixtures above carry the real assertion; this
    // one only adds the permission path where it actually applies.
    const readable = spawnSync("node", ["-e", `require("fs").readFileSync(${JSON.stringify(secret)})`]);
    if (readable.status === 0) {
      assert.ok(true, "running privileged: chmod 000 is not enforced, case not applicable");
      return;
    }
    const d = json(dir);
    assert.strictEqual(d.incomplete, true, "an unreadable file must still make the report incomplete");
    assert.match(d.summary.scope, /not scanned — could not be read/);
  });
});

test("a non-file path and a vanished path are their own reasons, both limitations", () => {
  withDir((dir) => {
    const config = mergeConfig({});
    mkdirSync(path.join(dir, "adir"));
    assert.deepStrictEqual(readTextFileResult(dir, "adir", config), { skipped: "not-a-file" });
    assert.deepStrictEqual(readTextFileResult(dir, "gone.txt", config), { skipped: "vanished" });

    // Neither is binary, and both still count as coverage limitations.
    assert.deepStrictEqual(coverageLimitations({ notAFileExcluded: 2 }), [
      "2 path(s) not scanned — not a regular file",
    ]);
    assert.deepStrictEqual(coverageLimitations({ vanishedExcluded: 3 }), [
      "3 file(s) not scanned — gone before they could be read",
    ]);

    // A DETERMINISTIC read failure that needs no permission bits: a
    // self-referential symlink. The path cannot be resolved, so it takes the
    // conservative `vanished` branch rather than being written off as binary.
    // This keeps a real unresolvable-path case covered for privileged users
    // too, where the chmod test below skips itself.
    symlinkSync(path.join(dir, "loop"), path.join(dir, "loop"));
    assert.deepStrictEqual(readTextFileResult(dir, "loop", config), { skipped: "vanished" });
  });
});

test("binary is the ONLY reason that is not a limitation", () => {
  // The whole contract in one assertion: every other reason still sets
  // `incomplete`, and an unknown-cause read stays conservative.
  assert.deepStrictEqual(coverageLimitations({ binaryExcluded: 99 }), []);
  for (const facts of [
    { unreadableExcluded: 1 },
    { notAFileExcluded: 1 },
    { vanishedExcluded: 1 },
    { oversizedExcluded: 1 },
    { outsideExcluded: 1 },
    { cancelled: true },
  ]) {
    assert.strictEqual(
      coverageLimitations(facts).length,
      1,
      `${JSON.stringify(facts)} must remain a coverage limitation`
    );
  }
});

test("cancellation still reports incomplete, and binary does not mask it", () => {
  assert.deepStrictEqual(coverageLimitations({ cancelled: true, binaryExcluded: 5 }), [
    "the scan was stopped before it finished",
  ]);
  // A stopped scan that also met binary files is incomplete for the stop alone.
  const both = coverageLimitations({ cancelled: true, binaryExcluded: 5, unreadableExcluded: 2 });
  assert.deepStrictEqual(both, [
    "the scan was stopped before it finished",
    "2 file(s) not scanned — could not be read",
  ]);
});

// ---------------------------------------------------------------------------
suite("\ncoverage classification — accounting and wording agree");

test("scanFiles reports each reason exactly once, and the counts add up", () => {
  withDir((dir) => {
    writeFileSync(path.join(dir, "app.js"), "const ok = 1;\n");
    writeBinary(dir, "a.png");
    writeBinary(dir, "b.png");
    mkdirSync(path.join(dir, "adir"));
    const reasons: string[] = [];
    const scanned = scanFiles(dir, ["app.js", "a.png", "b.png", "adir", "gone.txt"], mergeConfig({}), {
      onSkipped: (r) => reasons.push(r),
    });
    assert.deepStrictEqual(scanned.map((s) => s.path), ["app.js"]);
    assert.deepStrictEqual(reasons.sort(), ["binary", "binary", "not-a-file", "vanished"]);
    // One event, one disclosure: nothing is counted twice under two names.
    assert.strictEqual(reasons.length, 4);
  });
});

test("the scope sentence carries every clause separately, in order", () => {
  const all = describeScope(9, "file", {
    oversizedExcluded: 1,
    binaryExcluded: 2,
    unreadableExcluded: 3,
    notAFileExcluded: 4,
    vanishedExcluded: 5,
  });
  assert.strictEqual(
    all,
    "9 file(s); 1 file(s) not scanned — larger than maxFileSizeBytes " +
      "(raise it in .secretloop.json to cover them)" +
      "; 2 file(s) not scanned — binary" +
      "; 3 file(s) not scanned — could not be read" +
      "; 4 path(s) not scanned — not a regular file" +
      "; 5 file(s) not scanned — gone before they could be read"
  );
});

test("CLI text, JSON and SARIF all disclose the binary skip identically", () => {
  withDir((dir) => {
    writeFileSync(path.join(dir, "app.js"), "const ok = 1;\n");
    writeBinary(dir, "logo.png");
    const text = cli(["scan"], dir).stdout;
    const d = json(dir);
    const sarif = JSON.parse(cli(["scan", "--format", "sarif"], dir).stdout);
    const sarifScope = JSON.stringify(sarif);

    for (const [name, haystack] of [
      ["text", text],
      ["json", d.summary.scope],
      ["sarif", sarifScope],
    ] as const) {
      assert.match(haystack, /not scanned — binary/, `${name} lost the binary disclosure`);
    }
  });
});

// ---------------------------------------------------------------------------
suite("\ncoverage classification — what the binary classifier actually decides");

/**
 * The classifier is `NUL in the first 8000 bytes`. These pin its REAL boundary
 * so no later change can quietly claim it proves more than it does — in
 * particular that a binary skip means the file held no secret. It does not.
 */
test("UTF-16 text carrying a live-format token is classified binary", () => {
  withDir((dir) => {
    // UTF-16 pads ASCII with NUL, so real text lands in the binary bucket. The
    // reader is UTF-8 only and selects no decoder from a BOM, so such a file is
    // outside the supported scan scope either way — but it is NOT evidence the
    // file is clean, and the disclosure is what says so.
    writeFileSync(path.join(dir, "secret.txt"), Buffer.from(`token = "${TOKEN}"\n`, "utf16le"));
    const d = json(dir);
    assert.strictEqual(d.summary.scannedCount, 0, "UTF-16 text is not scanned");
    assert.strictEqual(d.findings.length, 0, "and its credential is therefore never found");
    assert.match(d.summary.scope, /1 file\(s\) not scanned — binary/,
      "the skip must stay visible: this is the only thing telling a reader nothing looked");
  });
});

test("text with an embedded NUL is classified binary, and nothing after it is read", () => {
  withDir((dir) => {
    writeFileSync(
      path.join(dir, "secret.txt"),
      Buffer.concat([Buffer.from("header\u0000marker\n"), Buffer.from(`token = "${TOKEN}"\n`)])
    );
    const d = json(dir);
    assert.strictEqual(d.findings.length, 0, "the token after the NUL is never reached");
    assert.match(d.summary.scope, /not scanned — binary/);
  });
});

test("a NUL past the 8000-byte window does NOT make the file binary", () => {
  withDir((dir) => {
    writeFileSync(
      path.join(dir, "late.txt"),
      Buffer.concat([
        Buffer.from(`token = "${TOKEN}"\n`),
        Buffer.from("x".repeat(9000)),
        Buffer.from([0]),
      ])
    );
    const d = json(dir);
    // The window is the boundary, not the presence of a NUL anywhere.
    assert.strictEqual(d.summary.scannedCount, 1, "scanned as text despite carrying a NUL");
    assert.strictEqual(d.findings.length, 1, "and the credential IS reported");
    assert.ok(!/not scanned — binary/.test(d.summary.scope));
  });
});

test("a binary skip is disclosed but never asserted to be clean", () => {
  withDir((dir) => {
    writeFileSync(path.join(dir, "app.js"), "const ok = 1;\n");
    writeBinary(dir, "blob.bin");
    const d = json(dir);
    const emitted = JSON.stringify(d);
    // `incomplete: false` says nothing the scan INTENDED to read failed. It does
    // not say the skipped file was examined, and nothing in the report claims a
    // skipped file is clean.
    assert.strictEqual(d.incomplete, false);
    assert.match(d.summary.scope, /not scanned — binary/);
    for (const overclaim of [/no secrets in/i, /verified clean/i, /contains no/i]) {
      assert.ok(!overclaim.test(emitted), `the report claimed more than it looked at: ${overclaim}`);
    }
  });
});

// ---------------------------------------------------------------------------
suite("\ncoverage classification — the meaning of `incomplete` changed");

test("the schema version moved, so the two meanings cannot silently compare", () => {
  // docs/reports.md: bumped when the MEANING of a comparison-bearing field
  // changes — explicitly including "what `incomplete` counts". A version-2
  // report saying `incomplete: true` may describe nothing worse than an image;
  // a version-3 report saying the same describes a real failure to look.
  assert.strictEqual(REPORT_SCHEMA_VERSION, 3);
  withDir((dir) => {
    writeFileSync(path.join(dir, "app.js"), "const ok = 1;\n");
    assert.strictEqual(json(dir).schemaVersion, 3, "emitted reports must carry the new version");
  });
});

test("the same tree that was incomplete under v2 is complete under v3, and says why", () => {
  withDir((dir) => {
    writeFileSync(path.join(dir, "app.js"), "const ok = 1;\n");
    writeBinary(dir, "logo.png");
    const d = json(dir);
    // Under schema 2 this exact tree reported incomplete: true with
    // ["1 file(s) not scanned — binary or unreadable"]. Both changed together —
    // which is precisely why the version had to move with them.
    assert.strictEqual(d.schemaVersion, 3);
    assert.strictEqual(d.incomplete, false);
    assert.deepStrictEqual(d.summary.coverage.limitations, []);
    assert.match(d.summary.scope, /not scanned — binary/);
  });
});

test("a supported ARCHIVE whose parser declined it stays a limitation, disclosed once", () => {
  withDir((dir) => {
    // A ZIP whose end-of-central-directory claims ZIP64: recognised magic, and
    // a parser that declines it. A supported binary format whose inspection
    // FAILED — it must not join the intentionally-excluded binary bucket.
    const z = buildZip([{ name: "a.txt", data: Buffer.from("plain text\n", "utf8") }]);
    const z64 = Buffer.from(z);
    const end = z64.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
    z64.writeUInt16LE(0xffff, end + 10);
    writeFileSync(path.join(dir, "broken.zip"), z64);
    writeFileSync(path.join(dir, "app.js"), "const ok = 1;\n");

    const skips: string[] = [];
    const notOpened: string[] = [];
    scanFiles(dir, ["app.js", "broken.zip"], mergeConfig({}), {
      onSkipped: (r) => skips.push(r),
      onContainerNotOpened: (r) => notOpened.push(r),
    });
    // Disclosed as a container that would not open, and NOT also as a binary
    // skip: one failure, one name. The binary split must not have reopened the
    // double-disclosure this guard exists to prevent.
    assert.deepStrictEqual(notOpened, ["unsupported-feature"]);
    assert.deepStrictEqual(skips, [], "an unopened container must not also count as a binary skip");

    const d = json(dir);
    assert.strictEqual(d.incomplete, true, "a declined container must still make the report incomplete");
  });
});

test("a report that still cannot look is incomplete under v3 too", () => {
  withDir((dir) => {
    writeFileSync(path.join(dir, "app.js"), "const ok = 1;\n");
    writeAdmittedDer(dir, "store.p12");
    const d = json(dir);
    assert.strictEqual(d.schemaVersion, 3);
    assert.strictEqual(d.incomplete, true, "v3 must not have weakened real failures");
  });
});

void finish();
