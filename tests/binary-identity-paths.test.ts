import { test, suite, finish, assert } from "./harness";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from "fs";
import { tmpdir } from "os";
import { spawnSync } from "child_process";
import * as path from "path";
import { binaryIdentity, BINARY_CONTRACT_VERSION } from "../src/report-metadata";

/**
 * THE INPUT CONTRACT OF `binaryIdentity`, AND THE TWO PRODUCTION GUARDS AROUND IT.
 *
 * `binaryIdentity` used to rewrite `\` to `/`. On POSIX a backslash is a legal
 * FILENAME character, so a real file named `dir\file.png` was mapped onto the
 * unrelated real path `dir/file.png` and both got one identity -- two different
 * exclusion sets reading as the same set.
 *
 * Tests here are in two clearly separated groups:
 *
 *   HELPER  -- `binaryIdentity` called directly. These pin the contract.
 *   SCANNER -- the real CLI over a real tree. These pin what a producer can
 *              actually reach, which is not the same question.
 *
 * PLATFORM. This file runs on the host that runs the suite. The separator
 * conversion for Windows producers happens in walk.ts
 * (`path.relative(...).split(path.sep).join("/")`), and on a POSIX host
 * `path.sep` is "/" so that conversion is the identity. Windows separator
 * handling is therefore asserted HERE ONLY AS THE CONTRACT THIS FUNCTION SEES --
 * a `/`-separated path -- and never as a native Windows run. Nothing in this
 * file executes on Windows, and no result here may be described as native
 * Windows validation.
 */

const CLI = path.join(__dirname, "..", "out", "cli.js");
const POSIX = process.platform !== "win32";

const cli = (args: string[], dir: string) =>
  spawnSync("node", [CLI, ...args, "--path", dir], { encoding: "utf8" });
const json = (dir: string) => JSON.parse(cli(["scan", "--format", "json"], dir).stdout);

function withDir(fn: (dir: string) => void): void {
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-binid-"));
  try {
    fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** A NUL byte in the first block: the binary heuristic, positively determined. */
function writeBinary(file: string): void {
  writeFileSync(file, Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0x00, 0x1a]));
}

function gitInit(dir: string): void {
  spawnSync("git", ["init", "-q", dir]);
  spawnSync("git", ["-C", dir, "config", "user.email", "t@t"]);
  spawnSync("git", ["-C", dir, "config", "user.name", "t"]);
  writeFileSync(path.join(dir, ".keep"), "x\n");
  spawnSync("git", ["-C", dir, "add", "-A"]);
  spawnSync("git", ["-C", dir, "commit", "-qm", "init"]);
}

// ---------------------------------------------------------------------------
suite("binaryIdentity path contract — HELPER");

test("HELPER: a literal-backslash name is refused, not folded onto the nested path", () => {
  // The defect, in one assertion. `dir\file.png` is ONE file on POSIX;
  // `dir/file.png` is a file inside a directory. They are not the same set.
  const backslash = binaryIdentity(["dir\\file.png"]);
  const nested = binaryIdentity(["dir/file.png"]);
  assert.strictEqual(backslash, undefined, "an ambiguous path withholds the digest");
  assert.match(String(nested), /^binary:[0-9a-f]{16}$/, "the nested path is ordinary and kept");
  assert.notStrictEqual(backslash, nested, "the two must never share an identity");
});

test("HELPER: refusal withholds the WHOLE set, and is not the empty set", () => {
  const mixed = binaryIdentity(["good.png", "bad\\name.png"]);
  assert.strictEqual(mixed, undefined, "one unrepresentable path withholds everything");
  assert.notStrictEqual(mixed, binaryIdentity([]), "never the empty-set digest");
  assert.notStrictEqual(
    mixed,
    binaryIdentity(["good.png"]),
    "the bad path is never dropped so the remaining subset can be hashed"
  );
});

test("HELPER: canonical paths hash to their documented version-2 identities", () => {
  // Pinned as literals so the representation cannot drift unnoticed. These are
  // BINARY_CONTRACT_VERSION 2 values.
  assert.strictEqual(binaryIdentity(["a.png"]), "binary:bed5ee7ee2f7ca04");
  assert.strictEqual(binaryIdentity(["./a.png"]), "binary:bed5ee7ee2f7ca04", "a leading ./ is stripped");
  assert.strictEqual(binaryIdentity(["dir/file.png"]), "binary:740fbb683ea4351d");
  assert.strictEqual(binaryIdentity([]), "binary:61b74cdb9db4e86c", "the empty set is a real identity");
});

test("HELPER: the contract version moved, so no version-1 digest can be reproduced", () => {
  // The bump is the whole point: a version-1 report and a version-2 report must
  // not compare silently. Under version 1 these were the values below, and
  // binary:113e0402775c6ac2 was ALSO what {"dir\\file.png"} collapsed onto --
  // which is why a version-1 digest must never be reachable from this build.
  assert.strictEqual(BINARY_CONTRACT_VERSION, 2, "the representation version");
  for (const stale of ["binary:3e511fbf408be70d", "binary:113e0402775c6ac2", "binary:4895676a188e8330"]) {
    for (const input of [["a.png"], ["./a.png"], ["dir/file.png"], [], ["b.png"], ["a/one.gif", "b/two.png"]]) {
      assert.notStrictEqual(binaryIdentity(input), stale, `version-1 digest ${stale} must be unreachable`);
    }
  }
});

test("HELPER: order independence and duplicate collapsing", () => {
  assert.strictEqual(
    binaryIdentity(["b/two.png", "a/one.gif", "b/two.png"]),
    binaryIdentity(["a/one.gif", "b/two.png"]),
    "duplicates collapse and order is irrelevant"
  );
  assert.strictEqual(
    binaryIdentity(["z/9.png", "a/1.png", "m/5.png"]),
    binaryIdentity(["m/5.png", "z/9.png", "a/1.png"]),
    "three paths, two orders, one identity"
  );
});

test("HELPER: the separator the contract accepts is /", () => {
  // What a Windows producer hands this function AFTER walk.ts converts
  // path.sep -- a `/`-separated relative path. Asserted as the contract, not as
  // a native Windows run: see the platform note at the top of this file.
  assert.strictEqual(
    binaryIdentity(["assets/img/logo.png"]),
    binaryIdentity(["assets/img/logo.png"]),
    "converted Windows output is an ordinary relative path here"
  );
  assert.match(String(binaryIdentity(["assets/img/logo.png"])), /^binary:[0-9a-f]{16}$/);
  // The UNCONVERTED spelling is refused rather than guessed at.
  assert.strictEqual(binaryIdentity(["assets\\img\\logo.png"]), undefined);
});

test("HELPER: empty set versus unavailable input", () => {
  assert.match(String(binaryIdentity([])), /^binary:[0-9a-f]{16}$/, "a measured empty set has an identity");
  assert.strictEqual(binaryIdentity(undefined), undefined, "unavailable accounting has none");
  assert.notStrictEqual(binaryIdentity([]), binaryIdentity(["x.png"]));
});

test("HELPER: absolute, drive and UNC paths are refused under the chosen contract", () => {
  assert.strictEqual(binaryIdentity(["/etc/secret.png"]), undefined, "absolute");
  assert.strictEqual(binaryIdentity(["C:/Users/x/a.png"]), undefined, "drive, slash spelling");
  assert.strictEqual(binaryIdentity(["C:\\Users\\x\\a.png"]), undefined, "drive, backslash spelling");
  assert.strictEqual(binaryIdentity(["//server/share/a.png"]), undefined, "UNC, slash spelling");
  assert.strictEqual(binaryIdentity(["\\\\server\\share\\a.png"]), undefined, "UNC, backslash spelling");
  assert.strictEqual(binaryIdentity([""]), undefined, "empty string");
  assert.strictEqual(binaryIdentity(["./"]), undefined, "./ alone names no file");
});

test("HELPER: non-canonical spellings are refused, so one file has one identity", () => {
  assert.strictEqual(binaryIdentity(["a//b.png"]), undefined, "repeated separator");
  assert.strictEqual(binaryIdentity(["a/./b.png"]), undefined, "dot segment");
  assert.strictEqual(binaryIdentity(["a/../b.png"]), undefined, "dot-dot segment");
  assert.strictEqual(binaryIdentity(["a/"]), undefined, "trailing separator");
});

test("HELPER: case and Unicode spellings stay DISTINCT; nothing is folded", () => {
  // Case folding would merge two genuinely different files on a case-sensitive
  // filesystem. Unicode normalization would decide a filesystem question this
  // function cannot answer. Neither is applied.
  assert.notStrictEqual(binaryIdentity(["A.png"]), binaryIdentity(["a.png"]), "case is preserved");
  assert.notStrictEqual(binaryIdentity(["Dir/f.png"]), binaryIdentity(["dir/f.png"]));
  assert.notStrictEqual(
    binaryIdentity(["caf\u00e9.png"]), // NFC
    binaryIdentity(["cafe\u0301.png"]), // NFD
    "NFC and NFD are different names and are not normalized together"
  );
  assert.notStrictEqual(binaryIdentity(["dirA/f.png"]), binaryIdentity(["dirB/f.png"]), "distinct directories");
});

test("HELPER: equal counts with different exclusion sets stay distinguishable", () => {
  const one = binaryIdentity(["a/1.png", "b/2.png"]);
  const two = binaryIdentity(["a/1.png", "b/3.png"]);
  assert.match(String(one), /^binary:[0-9a-f]{16}$/);
  assert.notStrictEqual(one, two, "two exclusions each, different sets, different identity");
  assert.strictEqual(
    binaryIdentity(["a/1.png", "b/2.png"]),
    binaryIdentity(["b/2.png", "a/1.png"]),
    "the same two, still one identity"
  );
});

// ---------------------------------------------------------------------------
suite("binaryIdentity path contract — SCANNER");

test("SCANNER: two unchanged legitimate exclusion sets keep one identity", () => {
  withDir((dir) => {
    gitInit(dir);
    mkdirSync(path.join(dir, "dir"));
    writeBinary(path.join(dir, "dir", "file.png"));
    writeFileSync(path.join(dir, "app.js"), "const a = 1;\n");
    const before = json(dir);
    writeFileSync(path.join(dir, "app.js"), "const a = 2;\nconst b = 3;\n");
    const after = json(dir);
    assert.match(String(before.binaryDigest), /^binary:[0-9a-f]{16}$/);
    assert.strictEqual(before.binaryDigest, after.binaryDigest, "the excluded set did not change");
    assert.strictEqual(before.incomplete, false);
    assert.strictEqual(after.incomplete, false);
  });
});

test("SCANNER: git enumeration refuses a backslash-named file and reports incomplete", () => {
  if (!POSIX) return; // such a name cannot exist on Windows
  withDir((dir) => {
    gitInit(dir);
    writeBinary(path.join(dir, "dir\\file.png"));
    const d = json(dir);
    // git quotes a path containing a backslash -- `"dir\\file.png"` -- whatever
    // core.quotePath is set to, so the enumeration is handed a path that does
    // not exist, the containment guard refuses it, and that refusal is a
    // coverage limitation. The file never reaches the binary classifier.
    assert.strictEqual(d.incomplete, true, "the refusal marks coverage incomplete");
    assert.ok(
      JSON.stringify(d.summary.coverage?.limitations ?? []).length > 2,
      "the limitation is disclosed"
    );
    assert.notStrictEqual(
      d.binaryDigest,
      "binary:740fbb683ea4351d",
      "it must never carry the identity of dir/file.png"
    );
  });
});

test("SCANNER: THE GUARD REGRESSION — the fallback enumeration admits it, and metadata must not collapse it", () => {
  if (!POSIX) return;
  // This is the combination that makes the collision REACHABLE: an enumeration
  // that admits the ambiguous path. Without git, listFilesWithExclusions falls
  // back to walkDirectory, which returns the real on-disk name and whose
  // containment guard accepts it -- so `dir\file.png` genuinely enters the
  // binary exclusion set.
  //
  // FAILS ON THE STARTING IMPLEMENTATION: both trees produced
  // binary:113e0402775c6ac2 with incomplete:false on both sides.
  //
  // If the enumeration ever starts admitting such a path on the git route too,
  // this test keeps the metadata side honest rather than silently collapsing.
  withDir((outer) => {
    const nested = path.join(outer, "A");
    const literal = path.join(outer, "B");
    mkdirSync(path.join(nested, "dir"), { recursive: true });
    mkdirSync(literal, { recursive: true });
    writeBinary(path.join(nested, "dir", "file.png"));
    writeBinary(path.join(literal, "dir\\file.png"));

    const a = json(nested);
    const b = json(literal);

    assert.match(String(a.binaryDigest), /^binary:[0-9a-f]{16}$/, "the nested tree has an identity");
    assert.strictEqual(
      b.binaryDigest,
      undefined,
      "the ambiguous exclusion withholds the digest entirely"
    );
    assert.notStrictEqual(a.binaryDigest, b.binaryDigest, "two different trees, never one identity");
    // Withheld, not replaced: the empty-set digest would claim nothing was excluded.
    assert.notStrictEqual(b.binaryDigest, "binary:61b74cdb9db4e86c");
  });
});

test("SCANNER: withholding leaves the rest of the report intact and findings unchanged", () => {
  if (!POSIX) return;
  withDir((dir) => {
    writeBinary(path.join(dir, "dir\\file.png"));
    writeFileSync(path.join(dir, "app.js"), "const a = 1;\n");
    const d = json(dir);
    assert.strictEqual(d.binaryDigest, undefined, "only the binary identity is withheld");
    assert.match(String(d.scopeDigest), /^scope:[0-9a-f]{16}$/, "the scope identity is untouched");
    assert.match(String(d.configDigest), /^[0-9a-f]{16}$/);
    assert.strictEqual(d.schemaVersion, 4, "no schema change was needed");
    assert.deepStrictEqual(d.findings, [], "detection is unaffected");
  });
});

finish();
