import { parseLogPatch } from "../src/history";
import { defaultConfig, mergeConfig } from "../src/config";
import { test, suite, finish, assert } from "./harness";

suite("history.ts");

const MARKER = "@@SGCOMMIT@@";
const SEP = "@@SGF@@";

function commitHeader(sha: string, subject = "add config"): string {
  return `${MARKER}${sha}${SEP}Dev <dev@example.com>${SEP}2026-01-01T00:00:00Z${SEP}${subject}`;
}

test("finds a secret in an added line", () => {
  const patch = [
    commitHeader("abc123def456"),
    "diff --git a/config.js b/config.js",
    "--- /dev/null",
    "+++ b/config.js",
    "@@ -0,0 +1,1 @@",
    '+const token = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";',
  ].join("\n");

  const findings = parseLogPatch(patch, defaultConfig);
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].ruleId, "github-token");
  assert.strictEqual(findings[0].file, "config.js");
  assert.strictEqual(findings[0].commit, "abc123def456");
});

test("computes the line number from the hunk header", () => {
  const patch = [
    commitHeader("aaa111"),
    "+++ b/app.js",
    "@@ -40,0 +41,1 @@",
    '+const token = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";',
  ].join("\n");
  assert.strictEqual(parseLogPatch(patch, defaultConfig)[0].line, 41);
});

test("ignores removed and context lines", () => {
  // A secret being DELETED in this commit was already reported when it was
  // added; re-reporting it on every removal would triple-count history.
  const patch = [
    commitHeader("bbb222"),
    "+++ b/app.js",
    "@@ -1,1 +1,1 @@",
    '-const token = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";',
    ' const other = "ghp_26C7e42F292c6912E7710c838347Ae178B4a";',
    "+const token = process.env.TOKEN;",
  ].join("\n");
  assert.strictEqual(parseLogPatch(patch, defaultConfig).length, 0);
});

test("reports a secret once even when many commits touch it", () => {
  const line = '+const token = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";';
  const patch = [
    commitHeader("c1"),
    "+++ b/app.js",
    "@@ -0,0 +1,1 @@",
    line,
    commitHeader("c2"),
    "+++ b/app.js",
    "@@ -1,1 +1,1 @@",
    line,
  ].join("\n");
  const findings = parseLogPatch(patch, defaultConfig);
  assert.strictEqual(findings.length, 1, "duplicate across commits must collapse");
  assert.strictEqual(findings[0].commit, "c1", "attributed to the first commit seen");
});

test("assembles a multi-line PEM block from consecutive added lines", () => {
  const patch = [
    commitHeader("ddd444"),
    "+++ b/id_rsa",
    "@@ -0,0 +1,4 @@",
    "+-----BEGIN RSA PRIVATE KEY-----",
    "+MIIEpAIBAAKCAQEA1c7+9z5Pad7OejecsQ0bu3aumnAxuNbaBcgVJcXOFbdc6JGf",
    "+MIIEpAIBAAKCAQEA1c7+9z5Pad7OejecsQ0bu3aumnAxuNbaBcgVJcXOFbdc6JGf",
    "+-----END RSA PRIVATE KEY-----",
  ].join("\n");
  const findings = parseLogPatch(patch, defaultConfig);
  assert.ok(
    findings.find((f) => f.ruleId === "private-key-block"),
    "a PEM block split across added lines must still be detected"
  );
});

test("skips files excluded by config", () => {
  const patch = [
    commitHeader("eee555"),
    "+++ b/node_modules/pkg/index.js",
    "@@ -0,0 +1,1 @@",
    '+const token = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";',
  ].join("\n");
  assert.strictEqual(parseLogPatch(patch, defaultConfig).length, 0);
});

test("respects a user-configured exclude path", () => {
  const config = mergeConfig({ excludePaths: ["testdata/**"] });
  const patch = [
    commitHeader("fff666"),
    "+++ b/testdata/keys.js",
    "@@ -0,0 +1,1 @@",
    '+const token = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";',
  ].join("\n");
  assert.strictEqual(parseLogPatch(patch, config).length, 0);
});

test("handles a deleted file (+++ /dev/null) without crashing", () => {
  const patch = [
    commitHeader("ggg777"),
    "+++ /dev/null",
    "@@ -1,1 +0,0 @@",
    '-const token = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";',
  ].join("\n");
  assert.strictEqual(parseLogPatch(patch, defaultConfig).length, 0);
});

test("counts commits scanned via the progress callback", () => {
  const patch = [commitHeader("h1"), commitHeader("h2"), commitHeader("h3")].join("\n");
  let last = 0;
  parseLogPatch(patch, defaultConfig, (n) => (last = n));
  assert.strictEqual(last, 3);
});

test("empty patch yields no findings", () => {
  assert.strictEqual(parseLogPatch("", defaultConfig).length, 0);
});

finish();
