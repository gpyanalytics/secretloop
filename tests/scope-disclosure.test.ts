import { test, suite, finish, assert } from "./harness";
import { mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { spawnSync } from "child_process";
import * as path from "path";
import { scanFiles } from "../src/workspace";
import { readTextFileResult } from "../src/walk";
import { mergeConfig } from "../src/config";
import { describeScope } from "../src/report";
import { positiveSamples } from "./fixtures";

/**
 * A file that was enumerated and then never read is disclosed.
 *
 * readTextFile returned null for four different situations -- not a file, over
 * maxFileSizeBytes, a NUL byte near the start, or any throw -- and scanFiles
 * dropped it with a bare `continue`. scannedCount is the size of the map that
 * survives, so the number simply shrank: a directory of 500 files where 480 sat
 * over the size cap reported "Scanned 20 file(s). No secrets found."
 *
 * Every other skip this scanner performs already names itself. This was the
 * last silent one and, on a real repository, the largest -- which makes it the
 * one place the governing invariant ("could not look" must never read as "found
 * nothing") was failing in the ordinary case rather than an exotic one.
 */

const CLI = path.join(__dirname, "..", "out", "cli.js");
const TOKEN = positiveSamples["github-token"];

function withTree(fn: (dir: string) => void): void {
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-scope-"));
  try {
    // One readable file so the scan has a non-zero count, and two carrying a
    // real credential that the reader refuses for different reasons.
    writeFileSync(path.join(dir, "app.js"), "const ok = 1;\n", "utf8");
    writeFileSync(
      path.join(dir, "big.js"),
      `const t = "${TOKEN}";\n` + "a".repeat(1_100_000),
      "utf8"
    );
    writeFileSync(
      path.join(dir, "bin.dat"),
      Buffer.concat([Buffer.from(`const t = "${TOKEN}";\n`), Buffer.from([0])])
    );
    fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const cli = (args: string[], dir: string) =>
  spawnSync("node", [CLI, ...args, "--path", dir], { encoding: "utf8" });

// ---------------------------------------------------------------------------
suite("scope disclosure — the reader says why, not just no");

test("readTextFileResult separates oversized from unreadable from outside", () => {
  withTree((dir) => {
    const config = mergeConfig({});
    assert.deepStrictEqual(readTextFileResult(dir, "big.js", config), { skipped: "oversized" });
    assert.deepStrictEqual(readTextFileResult(dir, "bin.dat", config), { skipped: "unreadable" });
    // A path that does not resolve is unreadable, NOT "outside": isInsideRoot
    // answers false for both, and only one of them is a containment event.
    assert.deepStrictEqual(readTextFileResult(dir, "nope.js", config), { skipped: "unreadable" });
    const ok = readTextFileResult(dir, "app.js", config);
    assert.ok("text" in ok && ok.text.includes("const ok"));
  });
});

test("scanFiles reports every file it could not read", () => {
  withTree((dir) => {
    const reasons: string[] = [];
    const scanned = scanFiles(dir, ["app.js", "big.js", "bin.dat"], mergeConfig({}), {
      onSkipped: (r) => reasons.push(r),
    });
    assert.deepStrictEqual(scanned.map((s) => s.path), ["app.js"]);
    assert.deepStrictEqual(reasons.sort(), ["oversized", "unreadable"]);
  });
});

test("an open buffer is scanned rather than counted as a skip", () => {
  // textFor wins over disk whatever the file's size, and that is not a skip:
  // counting it would report a disclosure for a file that was fully scanned.
  withTree((dir) => {
    const reasons: string[] = [];
    const scanned = scanFiles(dir, ["big.js"], mergeConfig({}), {
      textFor: () => `const t = "${TOKEN}";`,
      onSkipped: (r) => reasons.push(r),
    });
    assert.deepStrictEqual(reasons, [], "a file supplied from a buffer was counted as skipped");
    assert.strictEqual(scanned.length, 1);
    assert.ok(scanned[0].findings.some((f) => f.ruleId === "github-token"));
  });
});

// ---------------------------------------------------------------------------
suite("\nscope disclosure — text, json and sarif all say it");

test("the scope sentence names both counts, and the credentials are not reported", () => {
  withTree((dir) => {
    const out = cli(["scan"], dir);
    assert.strictEqual(out.status, 0, out.stderr);
    // The honest reading: one file scanned, two files not looked at. The old
    // output was "Scanned 1 file(s). No secrets found." with nothing else.
    assert.match(out.stdout, /Scanned 1 file\(s\)/);
    assert.match(
      out.stdout,
      /1 file\(s\) not scanned — larger than maxFileSizeBytes/,
      `the size-cap skip was silent:\n${out.stdout}`
    );
    assert.match(
      out.stdout,
      /1 file\(s\) not scanned — binary or unreadable/,
      `the binary skip was silent:\n${out.stdout}`
    );
    // And the disclosure is not a substitute for finding them: they really were
    // not scanned, so nothing about them is claimed either way.
    assert.ok(!out.stdout.includes(TOKEN));
  });
});

test("json carries both counts in the scope string", () => {
  withTree((dir) => {
    const d = JSON.parse(cli(["scan", "--format", "json"], dir).stdout);
    assert.strictEqual(d.summary.scannedCount, 1);
    assert.match(d.summary.scope, /larger than maxFileSizeBytes/, "JSON lost the size clause");
    assert.match(d.summary.scope, /binary or unreadable/, "JSON lost the unreadable clause");
  });
});

test("sarif carries them too, in the invocations block", () => {
  withTree((dir) => {
    const s = JSON.parse(cli(["scan", "--format", "sarif"], dir).stdout);
    const scope = s.runs[0].invocations[0].properties.scope;
    assert.match(scope, /larger than maxFileSizeBytes/, "SARIF lost the size clause");
    assert.match(scope, /binary or unreadable/, "SARIF lost the unreadable clause");
  });
});

test("the staged path discloses the same way", () => {
  // staged builds its list from git rather than from the walker, and goes
  // through the same scanFiles -- so it inherits the disclosure or it does not.
  withTree((dir) => {
    const git = (...a: string[]) => spawnSync("git", a, { cwd: dir, encoding: "utf8" });
    git("init", "-q", ".");
    git("add", "-A");
    const out = cli(["staged"], dir);
    assert.match(out.stdout, /larger than maxFileSizeBytes/, `staged was silent:\n${out.stdout}`);
    assert.match(out.stdout, /binary or unreadable/);
  });
});

test("a clean tree gains no clause at all", () => {
  // The other direction. A disclosure that always fires says nothing.
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-scope-"));
  try {
    writeFileSync(path.join(dir, "app.js"), "const ok = 1;\n", "utf8");
    const out = cli(["scan"], dir);
    assert.strictEqual(out.stdout.trim(), "Scanned 1 file(s). No secrets found.");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("raising maxFileSizeBytes removes the clause and finds the credential", () => {
  // Proves the clause names a real remedy rather than describing a wall.
  withTree((dir) => {
    writeFileSync(
      path.join(dir, ".secretloop.json"),
      JSON.stringify({ maxFileSizeBytes: 2_000_000 }),
      "utf8"
    );
    const d = JSON.parse(cli(["scan", "--format", "json"], dir).stdout);
    assert.doesNotMatch(d.summary.scope, /larger than maxFileSizeBytes/);
    assert.ok(
      d.findings.some((f: { file: string }) => f.file === "big.js"),
      "raising the cap did not bring the oversized file into scope"
    );
    // The binary file is still refused, and still says so.
    assert.match(d.summary.scope, /binary or unreadable/);
  });
});

// ---------------------------------------------------------------------------
suite("\nscope disclosure — the clauses compose");

test("describeScope carries each clause only when nonzero, alongside the other four", () => {
  assert.strictEqual(describeScope(9, "file", {}), "9 file(s)");
  assert.strictEqual(
    describeScope(9, "file", { oversizedExcluded: 2 }),
    "9 file(s); 2 file(s) not scanned — larger than maxFileSizeBytes " +
      "(raise it in .secretloop.json to cover them)"
  );
  assert.strictEqual(
    describeScope(9, "file", { unreadableExcluded: 3 }),
    "9 file(s); 3 file(s) not scanned — binary or unreadable"
  );
  const all = describeScope(9, "file", {
    generatedExcluded: 1,
    suppressed: 2,
    outsideExcluded: 3,
    fixtureSuppressed: 4,
    oversizedExcluded: 5,
    unreadableExcluded: 6,
  });
  for (const clause of [
    /1 generated file/,
    /2 finding\(s\) suppressed by inline/,
    /3 file\(s\) excluded \(symlinks/,
    /4 generic finding\(s\) suppressed in test/,
    /5 file\(s\) not scanned — larger than maxFileSizeBytes/,
    /6 file\(s\) not scanned — binary or unreadable/,
  ]) {
    assert.match(all, clause, `clause missing when all six compose: ${all}`);
  }
});

finish();
