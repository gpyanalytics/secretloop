import { test, suite, finish, assert } from "./harness";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { spawnSync } from "child_process";
import * as path from "path";
import { isFixturePath, FIXTURE_PATH_SEGMENTS, mergeConfig } from "../src/config";
import { scanText } from "../src/scanner";
import { describeScope } from "../src/report";

/**
 * Generic-tier findings in test, fixture and example paths are suppressed by
 * default, counted, and disclosed. Named provider rules are untouched: a real
 * `ghp_` in a fixture is still a leaked credential and still reports.
 *
 * Measured justification: on 185 KLOC of real code, 151 of 151 false positives
 * came from the two generic rules and 135 of them sat in these paths.
 */

const CLI = path.join(__dirname, "..", "out", "cli.js");
const GENERIC_VALUE = 'password = "Zr7Kq2Vh9Lm4Xt6Bn8WdQp1Sx3Tj5Yc"';
function token(salt = 1): string {
  const a = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let out = "";
  for (let i = 0; i < 36; i++) out += a[(i * 17 + salt * 7 + 5) % a.length];
  return "ghp_" + out;
}

function withRepo(files: Record<string, string>, fn: (dir: string) => void): void {
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-fixscope-"));
  try {
    for (const [rel, body] of Object.entries(files)) {
      const full = path.join(dir, rel);
      mkdirSync(path.dirname(full), { recursive: true });
      writeFileSync(full, body, "utf8");
    }
    fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
const cli = (args: string[], dir: string) =>
  spawnSync("node", [CLI, ...args, "--path", dir], { encoding: "utf8" });

// ---------------------------------------------------------------------------
suite("fixture scope — the path set");

test("every documented segment is recognised, and only as a whole segment", () => {
  const expected = [
    "__fixtures__", "__mocks__", "__snapshots__", "__test__", "__tests__",
    "examples", "fixtures", "snapshots", "test", "tests",
  ];
  assert.deepStrictEqual([...FIXTURE_PATH_SEGMENTS].sort(), expected);
  for (const seg of expected) {
    assert.ok(isFixturePath(`${seg}/a.js`), `${seg}/ not recognised`);
    assert.ok(isFixturePath(`packages/x/${seg}/a.js`), `nested ${seg}/ not recognised`);
  }
  // Substring matches are not segment matches.
  for (const p of ["src/testing/a.js", "src/latest/a.js", "contests/a.js", "src/examples.js"]) {
    assert.ok(!isFixturePath(p), `${p} was treated as a fixture path`);
  }
});

// ---------------------------------------------------------------------------
suite("fixture scope — suppression, both directions");

test("a generic finding inside a fixture path is suppressed, counted and disclosed", () => {
  withRepo({ "test/conf.js": GENERIC_VALUE + "\n", "src/app.js": "const ok = 1;\n" }, (dir) => {
    const out = cli(["scan"], dir);
    assert.match(out.stdout, /No secrets found/, `not suppressed:\n${out.stdout}`);
    assert.match(
      out.stdout,
      /1 generic finding\(s\) suppressed in test\/fixture paths \(--include-fixtures to report them\)/,
      `the suppression was silent:\n${out.stdout}`
    );
  });
});

test("BOTH halves of the generic tier are suppressed, not just the shape rule", () => {
  // This test exists because its absence let the fix ship covering half the
  // tier. `genericRuleIds` is built from rules.filter(r => r.generic), and the
  // entropy pass synthesises its findings rather than matching a SecretRule --
  // so generic-high-entropy is not in that set. The suite was green, corpus B
  // fell 151 -> 87 instead of 151 -> 2, and only the benchmark noticed.
  const entropyOnly = 'const blob = "Zr7Kq2Vh9Lm4Xt6Bn8WdQp1Sx3Tj5YcAb9Cd";\n';
  withRepo({ "src/x.js": entropyOnly }, (dir) => {
    const d = JSON.parse(cli(["scan", "--format", "json"], dir).stdout);
    assert.strictEqual(d.summary.total, 1, "fixture is not entropy-detectable; the test proves nothing");
    assert.strictEqual(d.findings[0].ruleId, "generic-high-entropy");
  });
  withRepo({ "test/x.js": entropyOnly }, (dir) => {
    const d = JSON.parse(cli(["scan", "--format", "json"], dir).stdout);
    assert.strictEqual(d.summary.total, 0, "an entropy-tier finding in a fixture path was NOT suppressed");
    assert.match(d.summary.scope, /1 generic finding\(s\) suppressed in test\/fixture paths/);
  });
});

test("the SAME value outside a fixture path is reported", () => {
  withRepo({ "src/conf.js": GENERIC_VALUE + "\n" }, (dir) => {
    const d = JSON.parse(cli(["scan", "--format", "json"], dir).stdout);
    assert.strictEqual(d.summary.total, 1, "a generic finding outside fixtures was suppressed");
    assert.doesNotMatch(d.summary.scope, /suppressed in test\/fixture paths/);
  });
});

test("a named-rule credential inside a fixture path still reports", () => {
  // The whole point: a real leaked token in a test file is a leaked token.
  withRepo({ "test/creds.js": `const t = "${token(3)}";\n` }, (dir) => {
    const d = JSON.parse(cli(["scan", "--format", "json"], dir).stdout);
    assert.strictEqual(d.summary.total, 1, "a named-rule credential was suppressed in a fixture");
    assert.strictEqual(d.findings[0].ruleId, "github-token");
  });
});

test("--include-fixtures restores everything", () => {
  withRepo({ "test/conf.js": GENERIC_VALUE + "\n" }, (dir) => {
    const d = JSON.parse(cli(["scan", "--format", "json", "--include-fixtures"], dir).stdout);
    assert.strictEqual(d.summary.total, 1);
    assert.doesNotMatch(d.summary.scope ?? "", /suppressed in test\/fixture paths/);
  });
});

test("the disclosure reaches json and sarif, not only text", () => {
  withRepo({ "test/conf.js": GENERIC_VALUE + "\n", "src/app.js": "const ok = 1;\n" }, (dir) => {
    const j = JSON.parse(cli(["scan", "--format", "json"], dir).stdout);
    const s = JSON.parse(cli(["scan", "--format", "sarif"], dir).stdout);
    const clause = /1 generic finding\(s\) suppressed in test\/fixture paths/;
    assert.match(j.summary.scope, clause, "JSON lost the clause");
    assert.match(s.runs[0].invocations[0].properties.scope, clause, "SARIF lost the clause");
  });
});

test("history is covered too", () => {
  withRepo({ "test/conf.js": GENERIC_VALUE + "\n" }, (dir) => {
    const git = (...a: string[]) => spawnSync("git", a, { cwd: dir, encoding: "utf8" });
    git("init", "-q", ".");
    git("add", "-A");
    git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-qm", "x");
    const d = JSON.parse(cli(["history", "--format", "json"], dir).stdout);
    assert.strictEqual(d.summary.total, 0, "history reported a suppressed generic finding");
    assert.match(d.summary.scope, /suppressed in test\/fixture paths/);
  });
});

test("scanText suppresses only generic rules, and says how many", () => {
  let n = 0;
  const findings = scanText(`${GENERIC_VALUE}\nconst t = "${token(4)}";\n`, {
    filePath: "test/both.js",
    config: mergeConfig({}),
    onFixtureSuppressed: (c) => (n += c),
  });
  assert.deepStrictEqual(findings.map((f) => f.ruleId), ["github-token"]);
  assert.strictEqual(n, 1);
});

test("describeScope carries the clause only when nonzero, alongside the others", () => {
  assert.strictEqual(describeScope(5, "file", {}), "5 file(s)");
  assert.strictEqual(
    describeScope(5, "file", { fixtureSuppressed: 4 }),
    "5 file(s); 4 generic finding(s) suppressed in test/fixture paths (--include-fixtures to report them)"
  );
  const all = describeScope(5, "file", {
    generatedExcluded: 1, suppressed: 2, outsideExcluded: 3, fixtureSuppressed: 4,
  });
  for (const c of [/1 generated file/, /2 finding\(s\) suppressed by inline/, /3 file\(s\) excluded \(symlinks/, /4 generic finding\(s\) suppressed in test/]) {
    assert.match(all, c, `clause missing when all four compose: ${all}`);
  }
});

finish();
