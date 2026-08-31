import { test, suite, finish, assert } from "./harness";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { spawnSync } from "child_process";
import * as path from "path";
import { baseExcludePaths, generatedExcludePaths } from "../src/rules";
import { classifyPath, defaultConfig } from "../src/config";

/**
 * 0.1.3 — `go.work.sum` joins `go.sum`.
 *
 * `baseExcludePaths` has carried `**​/go.sum` since the beginning. Go workspaces
 * (Go 1.18+) put exactly the same content -- module paths, versions and
 * checksums -- in a second file named `go.work.sum`, and that one was never
 * listed. A public Go repository produced 44 `generic-high-entropy` findings
 * from a single `go.work.sum`, every one of them a module digest.
 *
 * The base group, beside `go.sum`, and NOT the generated group. Consistency is
 * the whole argument: identical file class, identical content, and checksums
 * are never credentials. A file in the base group is one no flag can switch
 * back on, which is already true of `go.sum` -- so `--include-generated`
 * restores NEITHER, and the test below asserts that rather than assuming it.
 *
 * Fixtures are built in a temp directory rather than committed, because
 * findRepoRoot walks up to the enclosing git repository and a fixture under
 * tests/ would be scanned as part of SecretLoop itself.
 */

const CLI = path.join(__dirname, "..", "out", "cli.js");

function withDir(fn: (dir: string) => void): void {
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-gowork-"));
  try {
    fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function write(dir: string, rel: string, body: string): void {
  const full = path.join(dir, rel);
  mkdirSync(path.dirname(full), { recursive: true });
  writeFileSync(full, body, "utf8");
}

/**
 * Checksum-manifest content in the real `go.work.sum` shape: a module path, a
 * version, and a base64 digest. Generated rather than written literally, so
 * this file carries no high-entropy constant of its own.
 */
function checksumManifest(lines = 8): string {
  const alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";
  let out = "";
  for (let i = 0; i < lines; i++) {
    let digest = "";
    for (let k = 0; k < 43; k++) digest += alpha[(k * 31 + i * 13 + 7) % alpha.length];
    out += `github.com/example/module${i} v1.${i}.0/go.mod h1:${digest}=\n`;
  }
  return out;
}

function scanJson(dir: string, extra: string[] = []): { file: string; ruleId: string }[] {
  const res = spawnSync("node", [CLI, "scan", "--format", "json", ...extra, "--path", dir], {
    encoding: "utf8",
  });
  return JSON.parse(res.stdout).findings ?? [];
}

const filesIn = (findings: { file: string }[]) =>
  new Set(findings.map((f) => f.file.split(path.sep).join("/")));

// ---------------------------------------------------------------------------
suite("0.1.3 N3 — go.work.sum is excluded like go.sum");

/**
 * The pairing that keeps the exclusion tests from passing vacuously.
 *
 * If this content produced no findings under any name, every "is excluded"
 * assertion below would hold whether or not the exclusion existed. This proves
 * the manifest IS reportable, so the exclusion is what silences it.
 */
test("the fixture content reports when the file is not a checksum manifest", () => {
  withDir((dir) => {
    write(dir, "checksums.txt", checksumManifest());
    const files = filesIn(scanJson(dir));
    assert.ok(
      files.has("checksums.txt"),
      "the checksum fixture produced no findings at all, so the exclusion tests below would prove nothing"
    );
  });
});

test("go.work.sum is excluded by default", () => {
  withDir((dir) => {
    write(dir, "go.work.sum", checksumManifest());
    const files = filesIn(scanJson(dir));
    assert.ok(!files.has("go.work.sum"), "go.work.sum was scanned");
  });
});

test("go.work.sum is excluded in a subdirectory too", () => {
  withDir((dir) => {
    write(dir, "tools/go.work.sum", checksumManifest());
    const files = filesIn(scanJson(dir));
    assert.ok(!files.has("tools/go.work.sum"), "a nested go.work.sum was scanned");
  });
});

test("go.sum keeps the exclusion it already had", () => {
  withDir((dir) => {
    write(dir, "go.sum", checksumManifest());
    write(dir, "vendor-copy/go.sum", checksumManifest());
    const files = filesIn(scanJson(dir));
    assert.ok(!files.has("go.sum"), "go.sum stopped being excluded");
    assert.ok(!files.has("vendor-copy/go.sum"), "a nested go.sum stopped being excluded");
  });
});

/**
 * The criterion that changed after measurement rather than the placement.
 *
 * `--include-generated` empties `generatedExcludePaths` and only that array, so
 * it has never been able to switch `go.sum` back on. Putting `go.work.sum` in
 * the same group means the flag cannot switch that on either -- which is the
 * point of choosing consistency, and is asserted here so that a later move
 * between the two groups shows up as a failure rather than a surprise.
 */
test("--include-generated restores neither file", () => {
  withDir((dir) => {
    write(dir, "go.sum", checksumManifest());
    write(dir, "go.work.sum", checksumManifest());
    write(dir, "src/app.js", `const ok = 1;\n`);
    const files = filesIn(scanJson(dir, ["--include-generated"]));
    assert.ok(!files.has("go.sum"), "--include-generated scanned go.sum");
    assert.ok(!files.has("go.work.sum"), "--include-generated scanned go.work.sum");
  });
});

test("both files classify as base-group exclusions, not generated ones", () => {
  for (const rel of ["go.sum", "go.work.sum", "tools/go.work.sum", "a/b/go.sum"]) {
    assert.strictEqual(
      classifyPath(rel, defaultConfig),
      "excluded",
      `${rel} should be a base-group exclusion`
    );
  }
});

test("the pattern lives beside go.sum in the base group and nowhere else", () => {
  assert.ok(
    baseExcludePaths.includes("**/go.work.sum"),
    "**/go.work.sum is not in baseExcludePaths"
  );
  assert.ok(
    !generatedExcludePaths.includes("**/go.work.sum"),
    "**/go.work.sum must live in exactly one group"
  );
  // Adjacency is not cosmetic: the two entries share one justification, and a
  // reader who finds one should find the other without searching.
  const i = baseExcludePaths.indexOf("**/go.sum");
  assert.strictEqual(
    baseExcludePaths[i + 1],
    "**/go.work.sum",
    "**/go.work.sum should sit directly after **/go.sum"
  );
});

/**
 * `**​/go.sum` must not start matching `go.work.sum` by accident, and the new
 * pattern must not start matching `go.sum`. Both globs are exact filenames, and
 * this pins that: a future change to globToRegExp that made `.` a wildcard
 * would silently widen both.
 */
test("neither pattern matches the other file, or anything wider", () => {
  withDir((dir) => {
    write(dir, "go.work.sum.bak", checksumManifest());
    write(dir, "notgo.sum", checksumManifest());
    const files = filesIn(scanJson(dir));
    assert.ok(files.has("go.work.sum.bak"), "the exclusion widened past the exact filename");
    assert.ok(files.has("notgo.sum"), "the exclusion widened past the exact filename");
  });
});

finish();
