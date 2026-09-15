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
  binaryIdentity,
  REPORT_SCHEMA_VERSION,
} from "../src/report-metadata";
import { positiveSamples } from "./fixtures";
import { buildZip } from "./archive-builders";

/**
 * INTENTIONAL EXCLUSION IS NOT INABILITY TO INSPECT.
 *
 * `SkipReason` carried one bucket, `unreadable`, for four unrelated events: a
 * file classified binary, a path that was not a regular file, a path that had
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

/** A real git repo, so `root` is determinate and eligibility can be asserted. */
function gitInit(dir: string): void {
  spawnSync("git", ["init", "-q", dir]);
  spawnSync("git", ["-C", dir, "config", "user.email", "t@t"]);
  spawnSync("git", ["-C", dir, "config", "user.name", "t"]);
  writeFileSync(path.join(dir, ".keep"), "x\n");
  spawnSync("git", ["-C", dir, "add", "-A"]);
  spawnSync("git", ["-C", dir, "commit", "-qm", "init"]);
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

/**
 * REFERENCE MODEL -- NOT SHIPPED CODE.
 *
 * SecretLoop ships no comparator. This implements the nine-field eligibility
 * contract in docs/reports.md so the tests can assert what a CONFORMING
 * CONSUMER would decide. Every assertion using it is a statement about the
 * CONTRACT; assertions about findings, scope sentences and emitted fields are
 * statements about PRODUCT BEHAVIOUR. The two are labelled separately
 * throughout, and must never be read as the same claim.
 */
const PATTERNS: Record<string, RegExp> = {
  root: /^git:[0-9a-f]{16}$/,
  configDigest: /^[0-9a-f]{16}$/,
  ruleSetDigest: /^[0-9a-f]{16}$/,
  suppressionDigest: /^[0-9a-f]{16}$/,
  scopeDigest: /^scope:[0-9a-f]{16}$/,
  binaryDigest: /^binary:[0-9a-f]{16}$/,
};
function eligible(a: any, b: any): { ok: boolean; why: string[] } {
  const why: string[] = [];
  for (const r of [a, b]) {
    if (r?.schemaVersion !== 4) why.push(`unsupported schemaVersion ${r?.schemaVersion}`);
    if (r?.incomplete !== false) why.push("incomplete is not false in both");
  }
  if (a?.toolVersion !== b?.toolVersion) why.push("toolVersion differs");
  for (const r of [a, b]) {
    if (typeof r?.toolVersion !== "string" || r.toolVersion.trim() === "") why.push("toolVersion invalid");
  }
  for (const [f, re] of Object.entries(PATTERNS)) {
    for (const r of [a, b]) {
      const v = r?.[f];
      if (typeof v !== "string" || !re.test(v)) { why.push(`${f} missing or malformed`); }
    }
    if (a?.[f] !== b?.[f]) why.push(`${f} differs`);
  }
  return { ok: why.length === 0, why };
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

test("text with an embedded NUL is classified binary: read in full, scanned not at all", () => {
  withDir((dir) => {
    writeFileSync(
      path.join(dir, "secret.txt"),
      Buffer.concat([Buffer.from("header\u0000marker\n"), Buffer.from(`token = "${TOKEN}"\n`)])
    );
    const d = json(dir);
    // The file is READ in full -- the classifier runs on bytes already in
    // memory. What does not happen is SCANNING, so no rule sees the token.
    assert.strictEqual(d.findings.length, 0, "the token is never scanned, though its bytes were read");
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
  assert.strictEqual(REPORT_SCHEMA_VERSION, 4);
  withDir((dir) => {
    writeFileSync(path.join(dir, "app.js"), "const ok = 1;\n");
    assert.strictEqual(json(dir).schemaVersion, 4, "emitted reports must carry the new version");
  });
});

test("the same tree that was incomplete under v2 is complete under v4, and says why", () => {
  withDir((dir) => {
    writeFileSync(path.join(dir, "app.js"), "const ok = 1;\n");
    writeBinary(dir, "logo.png");
    const d = json(dir);
    // Under schema 2 this exact tree reported incomplete: true with
    // ["1 file(s) not scanned — binary or unreadable"]. Both changed together —
    // which is precisely why the version had to move with them.
    assert.strictEqual(d.schemaVersion, 4);
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

test("CLOSED: a NUL no longer turns a found secret into an eligible absence", () => {
  // The INVERSE of the gap this suite used to pin. Same scenario exactly; the
  // verdict is now the opposite, and `binaryDigest` is what changes it.
  //
  // SCANNER OUTPUT (product behaviour): the finding still disappears and
  // `incomplete` is still false -- that part was never the defect. What is new
  // is that the two reports no longer carry the same excluded-set identity.
  withDir((dir) => {
    const file = path.join(dir, "app.js");
    writeFileSync(file, `const token = "${TOKEN}";\n`);
    const a = json(dir);
    assert.strictEqual(a.findings.length, 1, "the credential is found first time");
    assert.strictEqual(a.incomplete, false);

    const withNul = Buffer.concat([Buffer.from("// \u0000\n"), Buffer.from(`const token = "${TOKEN}";\n`)]);
    writeFileSync(file, withNul);
    assert.ok(withNul.includes(Buffer.from(TOKEN)), "the credential must still be on disk");
    const b = json(dir);
    assert.strictEqual(b.findings.length, 0, "the finding is gone from the report");
    assert.strictEqual(b.incomplete, false, "and the report still claims completeness");

    // Everything else still matches -- which is exactly why a ninth field was
    // needed rather than a tweak to one of the existing eight.
    for (const f of ["schemaVersion", "toolVersion", "root", "configDigest",
                     "ruleSetDigest", "suppressionDigest", "scopeDigest"] as const) {
      assert.deepStrictEqual(a[f], b[f], `${f} differs; the pair would have failed on it anyway`);
    }
    // REFERENCE MODEL: the eligibility verdict.
    assert.notDeepStrictEqual(a.binaryDigest, b.binaryDigest,
      "the excluded set changed from {} to {app.js}; the pair MUST be incomparable");
    assert.strictEqual(eligible(a, b).ok, false, "a still-present credential must not read as removed");
  });
});

test("removing the NUL again is also incomparable", () => {
  withDir((dir) => {
    const file = path.join(dir, "app.js");
    writeFileSync(file, Buffer.concat([Buffer.from("// \u0000\n"), Buffer.from(`const t = "${TOKEN}";\n`)]));
    const a = json(dir);
    // Going the other way must fail too: a finding APPEARING because a file
    // left the binary set is no more comparable than one disappearing.
    writeFileSync(file, `const t = "${TOKEN}";\n`);
    const b = json(dir);
    assert.strictEqual(a.findings.length, 0);
    assert.strictEqual(b.findings.length, 1);
    assert.notDeepStrictEqual(a.binaryDigest, b.binaryDigest);
    assert.strictEqual(eligible(a, b).ok, false);
  });
});

test("equal exclusion COUNTS with different excluded paths are incomparable", () => {
  // The case a count could never catch: one file enters the binary set as
  // another leaves it, so "1 file(s) not scanned — binary" is identical in both
  // reports and only the SET distinguishes them.
  withDir((dir) => {
    const nul = (t: string) => Buffer.concat([Buffer.from("// \u0000\n"), Buffer.from(t)]);
    writeFileSync(path.join(dir, "a.js"), nul("const a = 1;\n"));
    writeFileSync(path.join(dir, "b.js"), "const b = 1;\n");
    const a = json(dir);
    writeFileSync(path.join(dir, "a.js"), "const a = 1;\n");
    writeFileSync(path.join(dir, "b.js"), nul("const b = 1;\n"));
    const b = json(dir);
    assert.match(a.summary.scope, /1 file\(s\) not scanned — binary/);
    assert.match(b.summary.scope, /1 file\(s\) not scanned — binary/, "the COUNTS are identical");
    assert.notDeepStrictEqual(a.binaryDigest, b.binaryDigest, "but the SETS differ");
    assert.strictEqual(eligible(a, b).ok, false);
  });
});

test("unchanged excluded images plus changed scanned text stays eligible", () => {
  // The benefit the schema-3 change exists to deliver must survive schema 4:
  // ordinary edits to scanned text keep comparing.
  withDir((dir) => {
    gitInit(dir);
    writeBinary(dir, "logo.png");
    writeFileSync(path.join(dir, "app.js"), "const a = 1;\n");
    const a = json(dir);
    writeFileSync(path.join(dir, "app.js"), "const a = 2;\nconst b = 3;\n");
    const b = json(dir);
    assert.deepStrictEqual(a.binaryDigest, b.binaryDigest, "the excluded set did not change");
    // REFERENCE MODEL: eligible.
    assert.strictEqual(eligible(a, b).ok, true, eligible(a, b).why.join("; "));
  });
});

test("exclusion order does not matter: the digest is over a set", () => {
  assert.strictEqual(
    binaryIdentity(["b/two.png", "a/one.gif", "b/two.png"]),
    binaryIdentity(["a/one.gif", "b/two.png"]),
    "duplicates collapse and order is irrelevant"
  );
  assert.strictEqual(
    binaryIdentity(["./a/one.gif", "a\\two.png"]),
    binaryIdentity(["a/one.gif", "a/two.png"]),
    "a leading ./ is stripped and separators are normalized"
  );
  assert.notStrictEqual(binaryIdentity(["a.png"]), binaryIdentity(["b.png"]));
});

test("empty set is an identity; unavailable accounting is not", () => {
  const empty = binaryIdentity([]);
  assert.match(String(empty), /^binary:[0-9a-f]{16}$/, "an empty set gets a real identity");
  assert.strictEqual(binaryIdentity(undefined), undefined, "unavailable accounting has none");
  assert.notStrictEqual(empty, binaryIdentity(["x.png"]));
  // Two scans that excluded nothing must compare with each other.
  assert.strictEqual(binaryIdentity([]), binaryIdentity([]));
});

test("an absolute path is refused rather than published", () => {
  // A report travels; a local layout has no business in one. Withholding makes
  // the pair ineligible, which is the safe direction.
  assert.strictEqual(binaryIdentity(["/etc/secret.png"]), undefined);
  assert.strictEqual(binaryIdentity(["C:/Users/x/a.png"]), undefined);
  assert.strictEqual(binaryIdentity([""]), undefined);
});

test("no file content, credential or absolute path reaches the digest", () => {
  // The digest input is names only. Same paths, wildly different contents.
  withDir((dir) => {
    writeFileSync(path.join(dir, "blob.bin"), Buffer.from([0x00, 0x01, 0x02]));
    const a = json(dir);
    writeFileSync(path.join(dir, "blob.bin"), Buffer.concat([Buffer.from([0]), Buffer.from(TOKEN)]));
    const b = json(dir);
    assert.deepStrictEqual(a.binaryDigest, b.binaryDigest,
      "contents changed, the path set did not, so the identity must not move");
    assert.ok(!JSON.stringify(b).includes(TOKEN), "no credential is emitted");
    assert.ok(!JSON.stringify(b).includes(dir), "no absolute path is emitted");
  });
});

test("PRODUCER TRACE: only a producer that observes exclusions claims the set", () => {
  withDir((dir) => {
    writeFileSync(path.join(dir, "app.js"), "const a = 1;\n");
    spawnSync("git", ["init", "-q", dir]);
    spawnSync("git", ["-C", dir, "config", "user.email", "t@t"]);
    spawnSync("git", ["-C", dir, "config", "user.name", "t"]);
    spawnSync("git", ["-C", dir, "add", "-A"]);
    spawnSync("git", ["-C", dir, "commit", "-qm", "init"]);

    const scan = json(dir);
    assert.match(String(scan.binaryDigest), /^binary:[0-9a-f]{16}$/,
      "a file scan observes every skip, so it may claim the set");

    // history reads blobs and emits no file-level exclusion events, so it
    // cannot establish the set and must NOT invent one.
    const hist = JSON.parse(cli(["history", "--format", "json"], dir).stdout);
    assert.ok(!("binaryDigest" in hist), "history must not fabricate an exclusion identity");
    assert.strictEqual(eligible(hist, hist).ok, false, "and is therefore ineligible");
  });
});

test("REFERENCE MODEL: invalid, missing or mismatched binaryDigest is rejected", () => {
  const base = {
    schemaVersion: 4, toolVersion: "0.5.1", root: "git:" + "a".repeat(16),
    configDigest: "b".repeat(16), ruleSetDigest: "c".repeat(16),
    suppressionDigest: "d".repeat(16), scopeDigest: "scope:" + "e".repeat(16),
    binaryDigest: "binary:" + "f".repeat(16), incomplete: false,
  };
  assert.strictEqual(eligible(base, { ...base }).ok, true, "the control pair must be eligible");

  const { binaryDigest, ...missing } = base;
  for (const [label, bad] of [
    ["missing", missing],
    ["null", { ...base, binaryDigest: null }],
    ["empty", { ...base, binaryDigest: "" }],
    ["whitespace", { ...base, binaryDigest: "   " }],
    ["wrong type", { ...base, binaryDigest: 7 }],
    ["malformed", { ...base, binaryDigest: "binary:xyz" }],
    ["unprefixed", { ...base, binaryDigest: "f".repeat(16) }],
    ["mismatched", { ...base, binaryDigest: "binary:" + "0".repeat(16) }],
  ] as const) {
    assert.strictEqual(eligible(base, bad as any).ok, false, `${label} binaryDigest must be rejected`);
  }
  // A shared absence is still an absence.
  assert.strictEqual(eligible(missing as any, missing as any).ok, false,
    "two reports that BOTH omit it are not thereby comparable");
});

test("REFERENCE MODEL: schema versions 1, 2 and 3 are unsupported", () => {
  const ok = {
    schemaVersion: 4, toolVersion: "0.5.1", root: "git:" + "a".repeat(16),
    configDigest: "b".repeat(16), ruleSetDigest: "c".repeat(16),
    suppressionDigest: "d".repeat(16), scopeDigest: "scope:" + "e".repeat(16),
    binaryDigest: "binary:" + "f".repeat(16), incomplete: false,
  };
  for (const v of [1, 2, 3, 99]) {
    assert.strictEqual(eligible({ ...ok, schemaVersion: v }, { ...ok, schemaVersion: v }).ok, false,
      `schemaVersion ${v} must be rejected even when both sides agree`);
  }
  // A version-3 report is rejected twice over: unsupported version AND no
  // binaryDigest, so nothing establishes which files it declined to look at.
  const { binaryDigest, ...v3 } = { ...ok, schemaVersion: 3 };
  const why = eligible(v3 as any, v3 as any).why.join("; ");
  assert.match(why, /schemaVersion/);
  assert.match(why, /binaryDigest/);
});

test("REFERENCE MODEL: a partial scan cannot claim complete accounting", () => {
  // incomplete gates before binaryDigest is ever consulted, so an interrupted
  // or failed scan is ineligible regardless of what set it managed to observe.
  const base = {
    schemaVersion: 4, toolVersion: "0.5.1", root: "git:" + "a".repeat(16),
    configDigest: "b".repeat(16), ruleSetDigest: "c".repeat(16),
    suppressionDigest: "d".repeat(16), scopeDigest: "scope:" + "e".repeat(16),
    binaryDigest: "binary:" + "f".repeat(16), incomplete: true,
  };
  assert.strictEqual(eligible(base, { ...base }).ok, false,
    "incomplete: true on both sides must not permit comparison");
});

test("a genuine read failure keeps a report ineligible even with a valid binaryDigest", () => {
  // PRODUCT BEHAVIOUR plus REFERENCE MODEL: the conservative paths are unchanged
  // by the new field.
  withDir((dir) => {
    writeFileSync(path.join(dir, "app.js"), "const ok = 1;\n");
    const clean = json(dir);
    writeAdmittedDer(dir, "store.p12");
    const failed = json(dir);
    assert.strictEqual(failed.incomplete, true, "an inconclusive supported-format read still fails");
    assert.strictEqual(eligible(clean, failed).ok, false);
  });
});

test("a report that still cannot look is incomplete under v4 too", () => {
  withDir((dir) => {
    writeFileSync(path.join(dir, "app.js"), "const ok = 1;\n");
    writeAdmittedDer(dir, "store.p12");
    const d = json(dir);
    assert.strictEqual(d.schemaVersion, 4);
    assert.strictEqual(d.incomplete, true, "v4 must not have weakened real failures");
  });
});

void finish();
