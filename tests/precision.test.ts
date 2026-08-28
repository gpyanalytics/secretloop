import { test, suite, finish, assert } from "./harness";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, readFileSync } from "fs";
import { tmpdir } from "os";
import { spawnSync } from "child_process";
import * as path from "path";
import {
  baseExcludePaths,
  generatedExcludePaths,
  defaultExcludePaths,
} from "../src/rules";
import { classifyPath, isPathExcluded, mergeConfig, defaultConfig } from "../src/config";
import { listFilesWithExclusions } from "../src/walk";
import { describeScope } from "../src/cli";
import { findHighEntropyStrings } from "../src/entropy";
import { scanText, Finding } from "../src/scanner";
import { render } from "../src/report";

/**
 * The 0.1.1 precision work: generated-file excludes, the URL/path entropy skip,
 * value-hash grouping in the text report, and the fail-on stderr hint.
 *
 * Fixtures are built in a temp directory rather than committed, for the reason
 * tests/mcp.test.ts documents: findRepoRoot walks up to the enclosing git
 * repository, so a fixture under tests/ is scanned as part of SecretLoop itself.
 */

const CLI = path.join(__dirname, "..", "out", "cli.js");

function withDir(fn: (dir: string) => void): void {
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-precision-"));
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
 * A credential-shaped value, generated rather than written literally so this
 * file carries no credential constant of its own.
 */
function token(salt = 1): string {
  // An alphabet, not a credential. secretloop:allow
  const alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let out = "";
  for (let i = 0; i < 36; i++) out += alpha[(i * 17 + salt * 7 + 5) % alpha.length];
  return "ghp_" + out;
}

function runCli(dir: string, args: string[]): { status: number | null; stdout: string; stderr: string } {
  const res = spawnSync("node", [CLI, ...args, "--path", dir], { encoding: "utf8" });
  return { status: res.status, stdout: res.stdout, stderr: res.stderr };
}

// ---------------------------------------------------------------------------
suite("0.1.1 — generated-file exclusion group");

/**
 * One fixture per pattern, each named like the generated type it stands for and
 * each carrying a credential-shaped value, so "skipped by default" and "found
 * with --include-generated" are both observable per pattern.
 */
const GENERATED_FIXTURES: Array<[label: string, rel: string]> = [
  ["cocoapods lockfile", "ios/Podfile.lock"],
  ["generic .lock", "deps/anything.lock"],
  ["gradle wrapper", "android/gradlew"],
  ["gradle wrapper (windows)", "android/gradlew.bat"],
  ["maven wrapper", "mvnw"],
  ["maven wrapper (windows)", "mvnw.cmd"],
  ["xcode project", "ios/App.xcodeproj/project.pbxproj"],
  ["xcode workspace", "ios/App.xcworkspace/contents.xcworkspacedata"],
  ["scan artifact", "results.sarif"],
];

test("every generated pattern is in the generated group, not the base group", () => {
  for (const pattern of generatedExcludePaths) {
    assert.ok(
      !baseExcludePaths.includes(pattern),
      `${pattern} must live in exactly one group, and it is in both`
    );
  }
  // The union is what the default config uses, so nothing stops being excluded.
  for (const pattern of [...baseExcludePaths, ...generatedExcludePaths]) {
    assert.ok(defaultExcludePaths.includes(pattern), `${pattern} missing from defaultExcludePaths`);
  }
});

test("each generated fixture is skipped by default and found with --include-generated", () => {
  for (const [label, rel] of GENERATED_FIXTURES) {
    withDir((dir) => {
      write(dir, rel, `const t = "${token()}";\n`);
      write(dir, "src/app.js", "const ok = 1;\n");

      const off = runCli(dir, ["scan", "--format", "json"]);
      const offData = JSON.parse(off.stdout);
      assert.strictEqual(offData.summary.total, 0, `${label} (${rel}) was scanned by default`);

      const on = runCli(dir, ["scan", "--format", "json", "--include-generated"]);
      const onData = JSON.parse(on.stdout);
      assert.strictEqual(
        onData.summary.total,
        1,
        `${label} (${rel}) was not scanned even with --include-generated`
      );
      assert.strictEqual(onData.findings[0].ruleId, "github-token");
    });
  }
});

test("skipped generated files are disclosed in the scope statement, counted by this group only", () => {
  withDir((dir) => {
    write(dir, "ios/Podfile.lock", `t = "${token(1)}"\n`);
    write(dir, "android/gradlew", `t = "${token(2)}"\n`);
    write(dir, "src/app.js", "const ok = 1;\n");
    // A pre-existing exclusion, which must NOT be counted in the generated total.
    write(dir, "node_modules/pkg/index.js", `const t = "${token(3)}";\n`);

    const res = runCli(dir, ["scan"]);
    assert.match(
      res.stdout,
      /2 generated file\(s\) excluded by default \(--include-generated to scan them\)/,
      `disclosure line missing or miscounted:\n${res.stdout}`
    );
    assert.doesNotMatch(res.stdout, /3 generated file/, "pre-existing exclusions were counted");
  });
});

test("a scan that skipped files never reads identically to one that did not", () => {
  withDir((dir) => {
    write(dir, "src/app.js", "const ok = 1;\n");
    const none = runCli(dir, ["scan"]).stdout;
    write(dir, "ios/Podfile.lock", `t = "${token()}"\n`);
    const some = runCli(dir, ["scan"]).stdout;
    assert.notStrictEqual(none, some, "identical output with and without skipped generated files");
    assert.doesNotMatch(none, /generated file\(s\) excluded/);
    assert.match(some, /generated file\(s\) excluded/);
  });
});

test("--include-generated leaves pre-existing exclusions active", () => {
  withDir((dir) => {
    // node_modules and package-lock.json are pre-existing exclusions. The flag
    // bypasses the generated group only; it is not "scan everything".
    write(dir, "node_modules/pkg/index.js", `const t = "${token(1)}";\n`);
    write(dir, "package-lock.json", `{"t": "${token(2)}"}\n`);
    write(dir, "ios/Podfile.lock", `t = "${token(3)}"\n`);

    const on = JSON.parse(runCli(dir, ["scan", "--format", "json", "--include-generated"]).stdout);
    assert.strictEqual(on.summary.total, 1, "the flag re-enabled pre-existing exclusions");
    assert.match(on.findings[0].file, /Podfile\.lock$/);
  });
});

test("classifyPath separates the two groups and lets the base group win an overlap", () => {
  const config = mergeConfig({});
  assert.strictEqual(classifyPath("ios/Podfile.lock", config), "generated");
  assert.strictEqual(classifyPath("node_modules/x/index.js", config), "excluded");
  assert.strictEqual(classifyPath("src/app.js", config), "none");
  // out/** is a base exclusion and *.sarif is generated; base must win, so this
  // is not counted as a generated skip and the disclosure cannot overstate.
  assert.strictEqual(classifyPath("out/results.sarif", config), "excluded");
  assert.strictEqual(isPathExcluded("ios/Podfile.lock", config), true);
});

test("an explicit user include pattern overrides the default generated exclusion", () => {
  withDir((dir) => {
    write(dir, "ios/Podfile.lock", `t = "${token()}"\n`);

    // Both halves asserted, so this cannot pass merely because the exclusion
    // does not exist yet — which is exactly how it passed in RED at first.
    const without = JSON.parse(runCli(dir, ["scan", "--format", "json"]).stdout);
    assert.strictEqual(without.summary.total, 0, "the fixture was not excluded by default");

    write(
      dir,
      ".secretloop.json",
      JSON.stringify({ includePaths: ["**/Podfile.lock"] }, null, 2) + "\n"
    );
    const withCfg = JSON.parse(runCli(dir, ["scan", "--format", "json"]).stdout);
    assert.strictEqual(withCfg.summary.total, 1, "user includePaths did not override the default");
    assert.match(withCfg.findings[0].file, /Podfile\.lock$/);
  });
});

test("listFilesWithExclusions reports the generated count alongside the files", () => {
  withDir((dir) => {
    write(dir, "src/app.js", "1\n");
    write(dir, "ios/Podfile.lock", "1\n");
    write(dir, "android/gradlew", "1\n");
    write(dir, "node_modules/p/i.js", "1\n");
    const out = listFilesWithExclusions(dir, mergeConfig({}));
    assert.strictEqual(out.files.length, 1);
    assert.strictEqual(out.generatedExcluded, 2);
  });
});

test("describeScope carries the disclosure and stays byte-identical without it", () => {
  assert.strictEqual(describeScope(214, "file"), "214 file(s)");
  assert.strictEqual(
    describeScope(214, "file", 12),
    "214 file(s); 12 generated file(s) excluded by default (--include-generated to scan them)"
  );
  assert.strictEqual(
    describeScope(0, "file"),
    "0 file(s) — nothing was scanned, so this is not a clean result"
  );
  assert.match(describeScope(0, "file", 3), /not a clean result; 3 generated file\(s\) excluded/);
});

// ---------------------------------------------------------------------------
suite("0.1.1 — URL / path entropy skip");

test("protocol-relative URLs no longer fire the entropy pass", () => {
  const urls = [
    "//d2wy8f7a9ursnm.cloudfront.net/v4.7.3/bugsnag.min.js",
    "//developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/Keys",
    "//github.com/sgerrand/alpine-pkg-glibc/releases/download/2.28-r0/glibc-2.28-r0.apk",
  ];
  for (const url of urls) {
    const hits = findHighEntropyStrings(`const u = "${url}";`, 4.3);
    assert.strictEqual(hits.length, 0, `still fired on ${url}`);
  }
});

test("host/path strings without a scheme no longer fire", () => {
  const hits = findHighEntropyStrings(`img = "855461928731.dkr.ecr.us-west-1.amazonaws.com/js"`, 4.3);
  assert.strictEqual(hits.length, 0);
});

test("relative filesystem paths no longer fire", () => {
  const paths = [
    "../node_modules/react-native/Libraries/ActionSheetIOS",
    "react-native/Libraries/TurboModule/RCTExport",
    "../node_modules/react-native/third-party-podspecs/DoubleConversion.podspec",
  ];
  for (const p of paths) {
    const hits = findHighEntropyStrings(`pod "${p}"`, 4.3);
    assert.strictEqual(hits.length, 0, `still fired on ${p}`);
  }
});

test("base64 blobs containing slashes still fire — the filter must not eat real secrets", () => {
  const blobs = [
    // Real high-entropy blobs, on purpose: this test is the guard that the new
    // URL/path filter does not eat genuine secrets. secretloop:allow
    "qDbEJFSgG0JExIT8aJ2f4DyubQhqaJX39iVbueZCPc9GAqhPc/6n+gLXxweDZo1wD8hG2nZKjmisIck2mjzRV/qLJjO1hZnZxdj8f7J1DbexB6LgTAXe/etb7aiMsc6dZ52NV7sqfaFuxmLUhAJScj49ivJBovrbD/DOa8hmBoY=",
    // secretloop:allow
    "X29QA8LjTZL9RHnoiYlprpIbv264e//KjL3Q4A/vWZ8QbIRD2MY8w9wuIfQEYHLGa7kf1EAGPoH/Ka3raj7s5+J4hOeCeMC0ZWUWdAem35FE7zGm8wJrCKFK5GD9LF+1LRxK+gBfKfeaJkwcbjv7tl0DEW1JNC9PS4cpI0DRJzM=",
  ];
  for (const blob of blobs) {
    const hits = findHighEntropyStrings(`key = "${blob}"`, 4.3);
    assert.strictEqual(hits.length, 1, "a real high-entropy blob stopped firing");
  }
});

test("a URL stops firing entropy while a token in the same file still fires its rule", () => {
  // Written this way after the first draft passed in RED for no reason: a token
  // embedded *inside* a URL never fired generic entropy anyway, because the
  // entropy pass already skips spans overlapping a rule match. So the two facts
  // are separated — a URL that independently fires entropy today, and a token
  // elsewhere in the same file — which makes both halves observable.
  const t = token();
  const url = "//developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/Keys";
  const ids = scanText(`const u = "${url}";\nconst k = "${t}";\n`).map((f) => f.ruleId);
  assert.ok(ids.includes("github-token"), `format rule stopped firing: ${ids.join(",")}`);
  assert.ok(!ids.includes("generic-high-entropy"), `the URL still fired generic entropy: ${ids.join(",")}`);
});

// ---------------------------------------------------------------------------
suite("0.1.1 — value-hash grouping in the text report");

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: "generic-high-entropy",
    description: "High-entropy string (entropy 4.90)",
    // A fixture value, credential-shaped so the grouping assertions are real.
    // secretloop:allow
    value: "Zr7Kq2Vh9Lm4Xt6Bn8WdQp1Sx3Tj5Yc",
    startIndex: 0,
    endIndex: 31,
    confidence: "entropy-heuristic",
    severity: "medium",
    line: 3,
    file: "a.js",
    fingerprint: "a.js:generic-high-entropy:1111111111111111",
    ...overrides,
  };
}

const opts = { redact: true, root: "/repo" };

test("one value in many places becomes one text entry listing every location", () => {
  const shared = [
    finding({ file: "a.js", line: 3, fingerprint: "a.js:generic-high-entropy:1111111111111111" }),
    finding({ file: "b.js", line: 9, fingerprint: "b.js:generic-high-entropy:2222222222222222" }),
    finding({ file: "c.js", line: 4, fingerprint: "c.js:generic-high-entropy:3333333333333333" }),
  ];
  const text = render(shared, "text", opts);
  // One entry, three locations.
  assert.strictEqual(
    (text.match(/High-entropy string/g) ?? []).length,
    1,
    `expected one grouped entry:\n${text}`
  );
  for (const loc of ["a.js:3", "b.js:9", "c.js:4"]) {
    assert.ok(text.includes(loc), `location ${loc} missing from the group:\n${text}`);
  }
  assert.match(text, /3 location/, "the group does not say how many locations it covers");
});

test("grouping does not change the finding count the report leads with", () => {
  const shared = [finding({ file: "a.js" }), finding({ file: "b.js" }), finding({ file: "c.js" })];
  const text = render(shared, "text", opts);
  assert.match(text, /3 finding\(s\)/, "the total stopped counting occurrences");
});

test("different values are never merged", () => {
  const two = [
    // Two distinct fixture values — the guard against over-merging.
    // secretloop:allow
    finding({ value: "Zr7Kq2Vh9Lm4Xt6Bn8WdQp1Sx3Tj5Yc", file: "a.js" }),
    // secretloop:allow
    finding({ value: "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv", file: "b.js" }),
  ];
  const text = render(two, "text", opts);
  assert.strictEqual((text.match(/High-entropy string/g) ?? []).length, 2);
});

test("SARIF still emits one result per occurrence, with every fingerprint intact", () => {
  const shared = [
    finding({ file: "a.js", line: 3, fingerprint: "a.js:generic-high-entropy:1111111111111111" }),
    finding({ file: "b.js", line: 9, fingerprint: "b.js:generic-high-entropy:2222222222222222" }),
    finding({ file: "c.js", line: 4, fingerprint: "c.js:generic-high-entropy:3333333333333333" }),
  ];
  const sarif = JSON.parse(render(shared, "sarif", opts));
  const results = sarif.runs[0].results;
  assert.strictEqual(results.length, 3, "grouping leaked into SARIF");
  const prints = results.map((r: any) => r.partialFingerprints["secretloopFingerprint/v2"]).sort();
  assert.deepStrictEqual(prints, [
    "a.js:generic-high-entropy:1111111111111111",
    "b.js:generic-high-entropy:2222222222222222",
    "c.js:generic-high-entropy:3333333333333333",
  ]);
});

test("JSON keeps one object per finding, with grouping added non-destructively", () => {
  const shared = [
    finding({ file: "a.js", fingerprint: "a.js:generic-high-entropy:1111111111111111" }),
    finding({ file: "b.js", fingerprint: "b.js:generic-high-entropy:2222222222222222" }),
  ];
  const json = JSON.parse(render(shared, "json", opts));
  assert.strictEqual(json.findings.length, 2, "JSON collapsed findings");
  for (const f of json.findings) {
    // The documented per-finding shape, unchanged.
    for (const key of ["ruleId", "description", "severity", "confidence", "verifyStatus", "file", "line", "fingerprint", "value"]) {
      assert.ok(key in f, `JSON finding lost its ${key} field`);
    }
  }
});

test("SARIF for an identical scanned input is unchanged by this release", () => {
  // The same-input compatibility fixture. Generated-file exclusion may change
  // WHICH results a default scan produces; for a fixed set of findings the
  // serializer and the fingerprints must be untouched.
  const input =
    'const a = "' + token(1) + '";\nconst b = "' + token(2) + '";\nconst c = "' + token(1) + '";\n';
  const findings = scanText(input, { filePath: "fixture.js" });
  const sarif = render(findings, "sarif", opts);
  const parsed = JSON.parse(sarif);
  assert.strictEqual(parsed.runs[0].results.length, findings.length);
  assert.deepStrictEqual(
    parsed.runs[0].results.map((r: any) => r.partialFingerprints["secretloopFingerprint/v2"]),
    findings.map((f) => f.fingerprint)
  );
  // Pinned so a future serializer change has to be deliberate.
  assert.strictEqual(parsed.version, "2.1.0");
  assert.strictEqual(parsed.runs[0].tool.driver.name, "SecretLoop");
});

// ---------------------------------------------------------------------------
suite("0.1.1 — fail-on stderr hint");

test("exiting 1 under a fail-on gate prints the hint to stderr", () => {
  withDir((dir) => {
    write(dir, "src/app.js", `const t = "${token()}";\n`);
    const res = runCli(dir, ["scan"]);
    assert.strictEqual(res.status, 1);
    assert.match(
      res.stderr,
      /exit 1: findings at or above the fail-on threshold \(this is the CI gate, not an error\)/,
      `hint missing from stderr:\n${res.stderr}`
    );
  });
});

test("a clean scan prints no hint and exits 0", () => {
  withDir((dir) => {
    write(dir, "src/app.js", "const ok = 1;\n");
    const res = runCli(dir, ["scan"]);
    assert.strictEqual(res.status, 0);
    assert.doesNotMatch(res.stderr, /exit 1:/);
  });
});

test("--fail-on never exits 0 and prints no hint even with findings", () => {
  withDir((dir) => {
    write(dir, "src/app.js", `const t = "${token()}";\n`);
    const res = runCli(dir, ["scan", "--fail-on", "never"]);
    assert.strictEqual(res.status, 0);
    assert.doesNotMatch(res.stderr, /exit 1:/);
  });
});

test("stdout is byte-identical to a run without the hint", () => {
  withDir((dir) => {
    write(dir, "src/app.js", `const t = "${token()}";\n`);
    const gated = runCli(dir, ["scan"]);
    const ungated = runCli(dir, ["scan", "--fail-on", "never"]);
    assert.strictEqual(
      gated.stdout,
      ungated.stdout,
      "the hint changed stdout; it must go to stderr only"
    );
  });
});

finish();
