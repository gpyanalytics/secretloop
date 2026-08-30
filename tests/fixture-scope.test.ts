import { test, suite, finish, assert } from "./harness";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { spawnSync } from "child_process";
import * as path from "path";
import { isFixturePath, FIXTURE_PATH_SEGMENTS, mergeConfig } from "../src/config";
import { scanText, isEntropyTier, isGenericTier } from "../src/scanner";
import { describeScope } from "../src/report";

/**
 * ENTROPY-tier findings in test, fixture and example paths are suppressed by
 * default, counted, and disclosed. Named provider rules are untouched: a real
 * `ghp_` in a fixture is still a leaked credential and still reports -- and
 * since 0.1.2 so is generic-api-key-assignment, which is a format-match.
 *
 * Measured justification: on 185 KLOC of real code, 151 of 151 false positives
 * came from the two generic rules and 135 of them sat in these paths.
 */

const CLI = path.join(__dirname, "..", "out", "cli.js");
const GENERIC_VALUE = 'password = "Zr7Kq2Vh9Lm4Xt6Bn8WdQp1Sx3Tj5Yc"';
// An entropy-tier value: no keyword in front, so no shape rule claims it.
// secretloop:allow
const ENTROPY_VALUE = 'const blob = "Zr7Kq2Vh9Lm4Xt6Bn8WdQp1Sx3Tj5YcAb9Cd";';
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

test("an entropy-tier finding inside a fixture path is suppressed, counted and disclosed", () => {
  // Was GENERIC_VALUE until 0.1.2. That value is a format-match and now reports
  // here by design, so it can no longer stand for "a suppressed finding".
  withRepo({ "test/conf.js": ENTROPY_VALUE + "\n", "src/app.js": "const ok = 1;\n" }, (dir) => {
    const out = cli(["scan"], dir);
    assert.match(out.stdout, /No secrets found/, `not suppressed:\n${out.stdout}`);
    assert.match(
      out.stdout,
      /1 generic finding\(s\) suppressed in test\/fixture paths \(--include-fixtures to report them\)/,
      `the suppression was silent:\n${out.stdout}`
    );
  });
});

test("the entropy half is suppressed and the format-match half is not", () => {
  // 0.1.1: "BOTH halves of the generic tier are suppressed, not just the shape
  // rule" -- written because the fix had shipped covering half the tier, and
  // corpus B fell 151 -> 87 instead of 151 -> 2 with a green suite.
  //
  // 0.1.2 deliberately re-splits them, the other way round. The entropy pass is
  // suppressible; generic-api-key-assignment is not, because it is a `high`
  // format-match and hiding it was a blindness bug. The lesson the old name
  // carried still holds -- reason about the tier explicitly, never by whichever
  // set is nearest -- which is why isEntropyTier exists as its own predicate.
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
  withRepo({ "test/conf.js": ENTROPY_VALUE + "\n" }, (dir) => {
    const d = JSON.parse(cli(["scan", "--format", "json", "--include-fixtures"], dir).stdout);
    assert.strictEqual(d.summary.total, 1);
    assert.doesNotMatch(d.summary.scope ?? "", /suppressed in test\/fixture paths/);
  });
});

test("the disclosure reaches json and sarif, not only text", () => {
  withRepo({ "test/conf.js": ENTROPY_VALUE + "\n", "src/app.js": "const ok = 1;\n" }, (dir) => {
    const j = JSON.parse(cli(["scan", "--format", "json"], dir).stdout);
    const s = JSON.parse(cli(["scan", "--format", "sarif"], dir).stdout);
    const clause = /1 generic finding\(s\) suppressed in test\/fixture paths/;
    assert.match(j.summary.scope, clause, "JSON lost the clause");
    assert.match(s.runs[0].invocations[0].properties.scope, clause, "SARIF lost the clause");
  });
});

test("history is covered too", () => {
  withRepo({ "test/conf.js": ENTROPY_VALUE + "\n" }, (dir) => {
    const git = (...a: string[]) => spawnSync("git", a, { cwd: dir, encoding: "utf8" });
    git("init", "-q", ".");
    git("add", "-A");
    git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-qm", "x");
    const d = JSON.parse(cli(["history", "--format", "json"], dir).stdout);
    assert.strictEqual(d.summary.total, 0, "history reported a suppressed generic finding");
    assert.match(d.summary.scope, /suppressed in test\/fixture paths/);
  });
});

test("scanText suppresses the entropy tier alone, and says how many", () => {
  // All three tiers in one call: a format-match, an entropy hit, and a named
  // rule. Only the middle one may disappear.
  let n = 0;
  const findings = scanText(
    `${GENERIC_VALUE}\n${ENTROPY_VALUE}\nconst t = "${token(4)}";\n`,
    {
      filePath: "test/both.js",
      config: mergeConfig({}),
      onFixtureSuppressed: (c) => (n += c),
    }
  );
  assert.deepStrictEqual(
    findings.map((f) => f.ruleId).sort(),
    ["generic-api-key-assignment", "github-token"],
    "the format-match was suppressed in a fixture path"
  );
  assert.strictEqual(n, 1, "exactly one entropy-tier finding should have been dropped");
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

// ---------------------------------------------------------------------------
suite("0.1.2 — HARD GATE: fixture suppression can never hide a real secret");

/**
 * The shipping gate for 0.1.2. 0.1.1 suppressed `isGenericTier`, which is
 * `generic-high-entropy` OR `genericRuleIds` -- and genericRuleIds' single
 * member is generic-api-key-assignment, a `severity: high`,
 * `confidence: format-match` rule. So a keyword-anchored API key in a test file
 * was hidden at default settings, and because suppression happens inside
 * scanText while verifyFindings runs afterwards on what scanText returned, a
 * *verified-live* credential in a fixture path could never report at all.
 *
 * The rule now: suppress the guess, never the certainty. Only the entropy tier
 * is suppressible.
 *
 * bugsnag-cocoa's [high] key in Tests/BugsnagTests/Data/BugsnagEvents/
 * BugsnagEvent1.json reported under 0.1.1 only because isFixturePath is
 * case-sensitive and that path says `Tests`, not `tests`. Luck, not design --
 * see the latent-issue note on FIXTURE_PATH_SEGMENTS in config.ts.
 */

test("GATE: a format-match credential in a fixture path reports at DEFAULT settings", () => {
  // The blindness bug, stated as an assertion. RED before the tier split.
  withRepo({ "tests/fixtures/conf.js": GENERIC_VALUE + "\n" }, (dir) => {
    const d = JSON.parse(cli(["scan", "--format", "json"], dir).stdout);
    assert.strictEqual(
      d.summary.total,
      1,
      "a format-match credential was hidden in a fixture path -- this is the blindness bug"
    );
    assert.strictEqual(d.findings[0].ruleId, "generic-api-key-assignment");
    assert.strictEqual(d.findings[0].confidence, "format-match");
    assert.strictEqual(d.findings[0].severity, "high");
  });
});

test("GATE: a real ghp_ token in a fixture path reports while entropy noise beside it is suppressed", () => {
  // Both halves in ONE file, so this cannot pass by the two behaviours being
  // measured in different places.
  //
  // This one was GREEN in RED, on purpose, and that is not evidence of
  // anything: named rules were already exempt in 0.1.1 and the entropy tier was
  // already suppressed. It is the anti-regression half of the gate -- the
  // property the tier split must not break. The RED came from the
  // format-match gate above.
  const body = `const t = "${token(5)}";\n${ENTROPY_VALUE}\n`;
  withRepo({ "tests/fixtures/creds.js": body }, (dir) => {
    const def = JSON.parse(cli(["scan", "--format", "json"], dir).stdout);
    assert.deepStrictEqual(
      def.findings.map((f: any) => f.ruleId),
      ["github-token"],
      "the token must report and the entropy noise must not, at default settings"
    );
    assert.match(def.summary.scope, /1 generic finding\(s\) suppressed in test\/fixture paths/);

    const inc = JSON.parse(cli(["scan", "--format", "json", "--include-fixtures"], dir).stdout);
    assert.deepStrictEqual(
      inc.findings.map((f: any) => f.ruleId).sort(),
      ["generic-high-entropy", "github-token"],
      "--include-fixtures must restore the entropy finding"
    );
  });
});

test("GATE: the suppressible set is the entropy tier alone, and is narrower than the generic tier", () => {
  // Makes the split observable rather than implied. If someone re-widens
  // suppression to the generic tier, this fails before any corpus notices.
  assert.strictEqual(isEntropyTier("generic-high-entropy"), true);
  assert.strictEqual(isEntropyTier("generic-api-key-assignment"), false);
  assert.strictEqual(isEntropyTier("github-token"), false);
  // The generic tier still has two members -- it is used for overlap merging,
  // which is a different policy and must not follow suppression.
  assert.strictEqual(isGenericTier("generic-high-entropy"), true);
  assert.strictEqual(isGenericTier("generic-api-key-assignment"), true);
  assert.strictEqual(isGenericTier("github-token"), false);
});


finish();
