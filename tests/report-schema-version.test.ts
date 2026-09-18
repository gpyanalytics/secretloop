import { test, suite, finish, assert } from "./harness";
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from "fs";
import { tmpdir } from "os";
import { spawnSync } from "child_process";
import * as path from "path";
import { REPORT_SCHEMA_VERSION } from "../src/report-metadata";

/**
 * SCHEMA 4 -> 5, MEASURED WITH REAL REPORTS.
 *
 * `incomplete` gained the opened-file check refusals (`replaced`, a kernel-path
 * `outside`, failed check evidence): a version-4 producer read such an object
 * and said `incomplete: false`; a version-5 producer says `true` for the same
 * event. That is the documented bump trigger -- "changing what `incomplete`
 * counts" -- so the version moved.
 *
 * `tests/fixtures/report-schema4-0.6.0.json` is a REAL report written by the
 * PUBLISHED npm package secretloop@0.6.0 (tarball sha256 1cb9ce16…, the
 * frozen release artifact) over a two-file synthetic repository with no
 * findings. It is committed byte for byte and must never be edited: it is
 * what a user who saved a 0.6.0 report actually holds.
 *
 * The schema-5 reports are produced here by the built CLI. Every exit code is
 * read from the child directly.
 */

const CLI = path.join(__dirname, "..", "out", "cli.js");
const FIXTURE = path.join(__dirname, "fixtures", "report-schema4-0.6.0.json");
const NINE = ["schemaVersion", "toolVersion", "root", "configDigest", "ruleSetDigest", "suppressionDigest", "scopeDigest", "binaryDigest", "incomplete"];

function withRepo(fn: (dir: string) => void): void {
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-schema5-"));
  try {
    const g = (...a: string[]) => {
      const r = spawnSync("git", ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", ...a], { cwd: dir, encoding: "utf8" });
      assert.strictEqual(r.status, 0, r.stderr);
    };
    writeFileSync(path.join(dir, "app.js"), "const ok = 1;\n");
    g("init", "-q");
    g("add", "-A");
    g("commit", "-q", "-m", "seed");
    fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function scan(dir: string): string {
  const r = spawnSync("node", [CLI, "scan", "--path", dir, "--format", "json", "--fail-on", "never"], { encoding: "utf8", timeout: 30000 });
  assert.strictEqual(r.status, 0, r.stderr);
  return r.stdout;
}

function compare(a: string, b: string): { status: number | null; json: any; text: string } {
  const j = spawnSync("node", [CLI, "compare", a, b, "--format", "json"], { encoding: "utf8", timeout: 30000 });
  const t = spawnSync("node", [CLI, "compare", a, b], { encoding: "utf8", timeout: 30000 });
  assert.strictEqual(j.status, t.status, "text and JSON forms exit alike");
  return { status: j.status, json: JSON.parse(j.stdout), text: t.stdout + t.stderr };
}

function token(salt: number): string {
  const a = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let out = "";
  for (let i = 0; i < 36; i++) out += a[(i * 17 + salt * 7 + 5) % a.length];
  return "ghp_" + out;
}

suite("report schema 5 — the constant, the producer and the published fixture");

test("the constant is 5 and every emitted working-tree report carries it", () => {
  assert.strictEqual(REPORT_SCHEMA_VERSION, 5);
  withRepo((dir) => {
    const d = JSON.parse(scan(dir));
    assert.strictEqual(d.schemaVersion, 5);
    for (const k of NINE) assert.ok(k in d, `${k} present`);
    assert.strictEqual(d.incomplete, false);
  });
});

test("the published 0.6.0 fixture is a genuine schema-4 report with all nine fields, and it is not touched by this build", () => {
  const raw = readFileSync(FIXTURE, "utf8");
  const d = JSON.parse(raw);
  assert.strictEqual(d.schemaVersion, 4);
  assert.strictEqual(d.toolVersion, "0.6.0");
  for (const k of NINE) assert.ok(k in d, `${k} present in the published report`);
  assert.strictEqual(d.incomplete, false);
  assert.ok(!("openedFileChecks" in d.summary.coverage), "a 0.6.0 report has no opened-file check block");
  // Read again after the comparator has been run over it below: unchanged.
  assert.strictEqual(readFileSync(FIXTURE, "utf8"), raw);
});

suite("report schema 5 — what the comparator in this build does with each pairing");

test("a schema-4 report against a schema-5 report is refused: unsupported-schema on the 4 side plus mixed-schema, exit 3, no difference computed", () => {
  withRepo((dir) => {
    const v5 = path.join(dir, "v5.json");
    writeFileSync(v5, scan(dir));
    for (const [a, b, side] of [[FIXTURE, v5, "before"], [v5, FIXTURE, "after"]] as const) {
      const r = compare(a, b);
      assert.strictEqual(r.status, 3, `an ineligible pair exits 3 (${side})`);
      assert.strictEqual(r.json.comparable, false);
      const reasons = r.json.reasons.map((x: { code: string; side: string; field?: string }) => [x.code, x.side, x.field]);
      // The version reasons come first and exactly so; the fixture's repository
      // is not this one, so identity mismatches follow them, and nothing else.
      assert.deepStrictEqual(reasons.slice(0, 2), [["unsupported-schema", side, "schemaVersion"], ["mixed-schema", "both", "schemaVersion"]]);
      assert.ok(reasons.slice(2).every((x: string[]) => x[0] === "identity-mismatch"), JSON.stringify(reasons));
      assert.match(r.json.reasons[0].detail, /schema 4 is not supported; this build implements 5/);
      for (const k of ["new", "persisting", "noLongerObserved"]) assert.ok(!(k in r.json), `no ${k} beside an incomparable verdict`);
      assert.match(r.text, /not comparable/);
    }
  });
});

test("TWO schema-4 reports are refused by this comparator too -- unsupported-schema on both sides, not only mixed pairs", () => {
  // Stated in the contract and pinned here because it is easy to assume the
  // bump only affects mixed pairs: a user holding two 0.6.0 reports cannot
  // compare them with this build. The 0.6.0 comparator still compares them.
  const r = compare(FIXTURE, FIXTURE);
  assert.strictEqual(r.status, 3);
  assert.strictEqual(r.json.comparable, false);
  assert.deepStrictEqual(
    r.json.reasons.map((x: { code: string; side: string }) => [x.code, x.side]),
    [["unsupported-schema", "before"], ["unsupported-schema", "after"]],
    "no mixed-schema reason: the versions agree, and both are unsupported"
  );
  for (const k of ["new", "persisting", "noLongerObserved"]) assert.ok(!(k in r.json));
});

test("an eligible schema-5 pair still compares: one added finding is reported as new, nothing else", () => {
  withRepo((dir) => {
    const before = path.join(dir, "before.json");
    const after = path.join(dir, "after.json");
    writeFileSync(before, scan(dir));
    writeFileSync(path.join(dir, "app.js"), `const ok = 1;\nconst t = "${token(3)}";\n`);
    writeFileSync(after, scan(dir));
    const r = compare(before, after);
    assert.strictEqual(r.status, 1, "compared, with new findings, exits 1");
    assert.strictEqual(r.json.comparable, true);
    assert.deepStrictEqual(r.json.summary, { new: 1, persisting: 0, noLongerObserved: 0, ambiguousIdentity: 0, sharedDisplayReferences: 0 });
    assert.strictEqual(r.json.new.length, 1);
    assert.strictEqual(r.json.new[0].ruleId, JSON.parse(readFileSync(after, "utf8")).findings[0].ruleId, "the new entry is the report's own finding");
    const same = compare(before, before);
    assert.strictEqual(same.status, 0, "compared, nothing new, exits 0");
    assert.deepStrictEqual(same.json.summary, { new: 0, persisting: 0, noLongerObserved: 0, ambiguousIdentity: 0, sharedDisplayReferences: 0 });
    assert.ok(!r.text.includes(token(3)), "the comparator prints no value");
  });
});

// A file refused by the opened-file checks makes its schema-5 report
// `incomplete: true` and the pair ineligible on `incomplete-coverage`; that
// case drives a real substitution through the CLI and lives beside the other
// scan-level cases in tests/opened-file-checks-scan.test.ts.

finish();
