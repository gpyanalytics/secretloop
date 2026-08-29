import { test, suite, finish, assert } from "./harness";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { spawnSync } from "child_process";
import * as path from "path";
import { redactValue, scanText } from "../src/scanner";
import { render, describeScope } from "../src/report";
import { getStagedFiles } from "../src/walk";
import { loadBaseline, resolveConfigFile, CONFIG_FILENAME } from "../src/config";
import { positiveSamples } from "./fixtures";

/**
 * The 0.1.1 rider: redaction hardened for short values, scope disclosed in the
 * machine-readable formats, staged enumeration that fails loudly, and two
 * smaller honesty fixes.
 *
 * Fixtures live outside the repository — findRepoRoot walks up to the enclosing
 * git repository, so a fixture under tests/ is scanned as part of SecretLoop
 * itself.
 */

const CLI = path.join(__dirname, "..", "out", "cli.js");

function withDir(fn: (dir: string) => void): void {
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-rider-"));
  try {
    fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function runCli(args: string[], dir: string) {
  const res = spawnSync("node", [CLI, ...args, "--path", dir], { encoding: "utf8" });
  return { status: res.status, stdout: res.stdout, stderr: res.stderr };
}

/** How many characters the mask leaves in place, positionally. */
function revealed(original: string, masked: string): number {
  let n = 0;
  for (let i = 0; i < Math.min(original.length, masked.length); i++) {
    if (masked[i] === original[i]) n++;
  }
  return n;
}

// An alphabet used to build values of an exact length, not a credential. The
// entropy pass cannot tell those apart by construction.
// secretloop:allow
const chars = (n: number) => "abcdefghijklmnopqrstuvwxyz0123456789".repeat(4).slice(0, n);

// ---------------------------------------------------------------------------
suite("rider — Fix 1: redactValue does not leak short secrets");

test("each length tier masks exactly as specified", () => {
  assert.strictEqual(redactValue(chars(8)), "********");
  assert.strictEqual(redactValue(chars(9)), chars(9).slice(0, 2) + "*******");
  assert.strictEqual(redactValue(chars(10)), chars(10).slice(0, 2) + "********");
  assert.strictEqual(redactValue(chars(15)), chars(15).slice(0, 2) + "*".repeat(13));
  // >= 16 is the unchanged tier: first four, capped asterisks, last four.
  assert.strictEqual(
    redactValue(chars(16)),
    chars(16).slice(0, 4) + "*".repeat(8) + chars(16).slice(-4)
  );
  assert.strictEqual(
    redactValue(chars(40)),
    chars(40).slice(0, 4) + "*".repeat(20) + chars(40).slice(-4)
  );
});

test("revealed characters never exceed the tier's budget", () => {
  const budget = (n: number) => (n <= 8 ? 0 : n < 16 ? 2 : 8);
  for (const n of [1, 4, 8, 9, 10, 12, 15, 16, 17, 24, 40, 64]) {
    const value = chars(n);
    const got = revealed(value, redactValue(value));
    assert.ok(
      got <= budget(n),
      `length ${n}: revealed ${got} characters, budget ${budget(n)} (${redactValue(value)})`
    );
  }
});

test("a suffix is never revealed below length 16", () => {
  for (const n of [9, 10, 12, 15]) {
    const value = chars(n);
    const masked = redactValue(value);
    assert.ok(
      masked.endsWith("*"),
      `length ${n} revealed its suffix: ${masked} — password material lives at these lengths`
    );
  }
});

test("no value under 16 characters keeps half its characters", () => {
  // Constructed rather than drawn from the corpus: the fixture set contains no
  // captured value shorter than 16 characters, so a corpus-only version of this
  // test asserted nothing. The guard that caught that is kept below.
  for (let n = 1; n <= 20; n++) {
    const value = chars(n);
    const ratio = revealed(value, redactValue(value)) / n;
    if (n < 16) {
      assert.ok(ratio < 0.5, `${n}-char value revealed ${Math.round(ratio * 100)}%`);
    }
  }
});

test("every value the corpus actually produces stays within its budget", () => {
  const values = Object.values(positiveSamples);
  assert.ok(values.length > 20, "fixture corpus is too small to be meaningful");
  let checked = 0;
  for (const sample of values) {
    for (const value of scanText(sample, { filePath: "f.txt" }).map((f) => f.value)) {
      checked++;
      const budget = value.length <= 8 ? 0 : value.length < 16 ? 2 : 8;
      assert.ok(
        revealed(value, redactValue(value)) <= budget,
        `${value.length}-char value exceeded its budget: ${redactValue(value)}`
      );
    }
  }
  assert.ok(checked > 20, `only ${checked} values scanned; the corpus arm is too thin`);
});

// ---------------------------------------------------------------------------
suite("rider — Fix 2: scope is disclosed in JSON and SARIF");

const sampleFinding = () => scanText(`const t = "${positiveSamples["github-token"]}";`, { filePath: "a.js" });

test("JSON carries the scope string, the count, and the noun", () => {
  const json = JSON.parse(
    render(sampleFinding(), "json", {
      redact: true,
      root: "/repo",
      scope: describeScope(412, "file"),
      scannedCount: 412,
      scopeNoun: "file",
    })
  );
  assert.strictEqual(json.summary.scope, "412 file(s)");
  assert.strictEqual(json.summary.scannedCount, 412);
  assert.strictEqual(json.summary.scopeNoun, "file");
  // Additive only: the documented per-finding shape is untouched.
  for (const key of ["ruleId", "severity", "confidence", "verifyStatus", "file", "line", "value"]) {
    assert.ok(key in json.findings[0], `JSON finding lost ${key}`);
  }
});

test("JSON says scope is null when the caller had nothing to say", () => {
  const json = JSON.parse(render(sampleFinding(), "json", { redact: true, root: "/repo" }));
  assert.strictEqual(json.summary.scope, null);
});

test("SARIF carries the scope in a schema-shaped invocation", () => {
  const sarif = JSON.parse(
    render(sampleFinding(), "sarif", {
      redact: true,
      root: "/repo",
      scope: describeScope(412, "file"),
      scannedCount: 412,
      scopeNoun: "file",
    })
  );
  const invocations = sarif.runs[0].invocations;
  assert.ok(Array.isArray(invocations) && invocations.length === 1, "no invocations array");
  const inv = invocations[0];
  // executionSuccessful is the only REQUIRED property of a SARIF invocation.
  assert.strictEqual(typeof inv.executionSuccessful, "boolean");
  assert.strictEqual(inv.properties.scope, "412 file(s)");
  // No invented siblings: anything outside the SARIF invocation vocabulary
  // belongs under properties, which is the bag the format provides for it.
  assert.deepStrictEqual(Object.keys(inv).sort(), ["executionSuccessful", "properties"]);
  assert.strictEqual(sarif.version, "2.1.0");
});

test("a zero-count enumeration says it is not a clean result in every format", () => {
  const scope = describeScope(0, "file");
  const opts = { redact: true, root: "/repo", scope, scannedCount: 0, scopeNoun: "file" };
  const text = render([], "text", opts);
  const json = JSON.parse(render([], "json", opts));
  const sarif = JSON.parse(render([], "sarif", opts));
  const wording = /nothing was scanned, so this is not a clean result/;
  assert.match(text, wording, "text lost the zero-count wording");
  assert.match(json.summary.scope, wording, "JSON lost the zero-count wording");
  assert.match(sarif.runs[0].invocations[0].properties.scope, wording, "SARIF lost it");
});

test("the generated-file disclosure reaches JSON and SARIF, not only text", () => {
  const scope = describeScope(214, "file", 12);
  const opts = { redact: true, root: "/repo", scope, scannedCount: 214, scopeNoun: "file" };
  const json = JSON.parse(render([], "json", opts));
  const sarif = JSON.parse(render([], "sarif", opts));
  const clause = /12 generated file\(s\) excluded by default/;
  assert.match(json.summary.scope, clause);
  assert.match(sarif.runs[0].invocations[0].properties.scope, clause);
});

test("end to end: a real CLI scan discloses scope in json and sarif", () => {
  withDir((dir) => {
    writeFileSync(path.join(dir, "app.js"), "const ok = 1;\n", "utf8");
    mkdirSync(path.join(dir, "ios"), { recursive: true });
    writeFileSync(path.join(dir, "ios", "Podfile.lock"), "PODS:\n", "utf8");

    const json = JSON.parse(runCli(["scan", "--format", "json"], dir).stdout);
    assert.strictEqual(json.summary.scannedCount, 1);
    assert.strictEqual(json.summary.scopeNoun, "file");
    assert.match(json.summary.scope, /1 file\(s\); 1 generated file\(s\) excluded by default/);

    const sarif = JSON.parse(runCli(["scan", "--format", "sarif"], dir).stdout);
    assert.match(
      sarif.runs[0].invocations[0].properties.scope,
      /1 file\(s\); 1 generated file\(s\) excluded by default/
    );
  });
});

// ---------------------------------------------------------------------------
suite("rider — Fix 3: a staged scan fails loudly when git cannot answer");

test("getStagedFiles distinguishes 'could not enumerate' from 'nothing staged'", () => {
  withDir((dir) => {
    // Not a git repository: git exits non-zero. Today this returns [], which is
    // indistinguishable from a clean index.
    const result = getStagedFiles(dir);
    assert.ok("error" in result, "a git failure was reported as an empty staged set");
    assert.match((result as { error: string }).error, /git/i);
  });
});

test("an empty index is still an empty list, not an error", () => {
  withDir((dir) => {
    const git = (...args: string[]) => spawnSync("git", args, { cwd: dir, encoding: "utf8" });
    git("init", "-q", ".");
    const result = getStagedFiles(dir);
    assert.ok("files" in result, "a clean index was reported as a failure");
    assert.deepStrictEqual((result as { files: string[] }).files, []);
  });
});

test("the staged command exits 2 and names the reason when git fails", () => {
  withDir((dir) => {
    writeFileSync(path.join(dir, "app.js"), "const ok = 1;\n", "utf8");
    const res = runCli(["staged"], dir);
    assert.strictEqual(res.status, 2, `expected exit 2, got ${res.status}\n${res.stdout}`);
    assert.match(res.stderr, /secretloop:/);
    assert.doesNotMatch(res.stdout, /No secrets found/, "it reported a scan that never happened");
    assert.doesNotMatch(res.stdout, /0 staged file\(s\)/, "a failure was rendered as an empty scan");
  });
});

test("an empty staged set still exits 0 with the zero-count wording", () => {
  withDir((dir) => {
    const git = (...args: string[]) => spawnSync("git", args, { cwd: dir, encoding: "utf8" });
    git("init", "-q", ".");
    writeFileSync(path.join(dir, "app.js"), "const ok = 1;\n", "utf8");
    const res = runCli(["staged"], dir);
    assert.strictEqual(res.status, 0, `expected exit 0, got ${res.status}\n${res.stderr}`);
    assert.match(res.stdout, /nothing was scanned, so this is not a clean result/);
  });
});

// ---------------------------------------------------------------------------
suite("rider — Fix 4: the example config describes the code that exists");

test("no document claims a .secretguard.json fallback", () => {
  const { readFileSync } = require("fs") as typeof import("fs");
  const repo = path.join(__dirname, "..");
  const docs = [".secretloop.example.json", "README.md", "docs/PRIMER.md", "docs/MARKET.md", "docs/ROADMAP.md"];
  for (const rel of docs) {
    let text = "";
    try {
      text = readFileSync(path.join(repo, rel), "utf8");
    } catch {
      continue;
    }
    assert.doesNotMatch(
      text,
      /secretguard\.json is still read|\.secretguard\.json/i,
      `${rel} still claims a .secretguard.json fallback that resolveConfigFile does not implement`
    );
  }
});

test("resolveConfigFile reads exactly one filename — pinned", () => {
  withDir((dir) => {
    writeFileSync(path.join(dir, ".secretguard.json"), "{}", "utf8");
    assert.strictEqual(resolveConfigFile(dir), null, "a legacy filename was read");
    writeFileSync(path.join(dir, CONFIG_FILENAME), "{}", "utf8");
    assert.ok(resolveConfigFile(dir), "the documented filename was not read");
  });
});

// ---------------------------------------------------------------------------
suite("rider — R1: a corrupt baseline names the file");

test("loadBaseline reports the filename and the reason", () => {
  withDir((dir) => {
    const file = path.join(dir, ".secretloop-baseline.json");
    writeFileSync(file, "{ not json", "utf8");
    let message = "";
    try {
      loadBaseline(file);
      assert.ok(false, "a corrupt baseline parsed without error");
    } catch (err) {
      message = (err as Error).message;
    }
    assert.match(message, /Could not parse \.secretloop-baseline\.json:/, `bare error: ${message}`);
  });
});

// ---------------------------------------------------------------------------
suite("rider — R2: inline suppressions are counted and disclosed");

test("describeScope appends the suppression clause only when nonzero", () => {
  assert.strictEqual(describeScope(10, "file", 0, 0), "10 file(s)");
  assert.strictEqual(
    describeScope(10, "file", 0, 3),
    "10 file(s); 3 finding(s) suppressed by inline directives"
  );
  // The three-argument form stays byte-identical, so the existing pins hold.
  assert.strictEqual(describeScope(10, "file", 2), describeScope(10, "file", 2, 0));
});

test("a scan counts findings dropped by secretloop:allow and gitleaks:allow", () => {
  withDir((dir) => {
    const t = positiveSamples["github-token"];
    writeFileSync(
      path.join(dir, "app.js"),
      [
        `const a = "${t}"; // secretloop:allow`,
        `const b = "${t}"; // gitleaks:allow`,
        "const c = 1;",
      ].join("\n"),
      "utf8"
    );
    const res = runCli(["scan"], dir);
    assert.match(
      res.stdout,
      /2 finding\(s\) suppressed by inline directives/,
      `suppressions were silent:\n${res.stdout}`
    );
    const json = JSON.parse(runCli(["scan", "--format", "json"], dir).stdout);
    assert.match(json.summary.scope, /2 finding\(s\) suppressed by inline directives/);
  });
});

test("a scan with no suppressions says nothing about them", () => {
  withDir((dir) => {
    writeFileSync(path.join(dir, "app.js"), "const ok = 1;\n", "utf8");
    const res = runCli(["scan"], dir);
    assert.doesNotMatch(res.stdout, /suppressed by inline directives/);
  });
});

finish();
