import { render, sortFindings } from "../src/report";
import { Finding } from "../src/scanner";
import { test, suite, finish, assert } from "./harness";

suite("report.ts");

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: "github-token",
    description: "GitHub Personal Access Token",
    value: "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
    startIndex: 0,
    endIndex: 40,
    confidence: "format-match",
    severity: "critical",
    line: 7,
    file: "src/app.ts",
    fingerprint: "src/app.ts:github-token:deadbeefdeadbeef",
    ...overrides,
  };
}

const opts = { redact: true, root: "/repo" };

test("redacts secret values by default", () => {
  const out = render([finding()], "text", opts);
  assert.ok(!out.includes("292c6912E7710c838347"), "raw secret must not appear in a report");
  assert.ok(out.includes("ghp_"), "a prefix is kept so the finding is identifiable");
});

test("--no-redact prints the full value when explicitly asked", () => {
  const out = render([finding()], "text", { ...opts, redact: false });
  assert.ok(out.includes("ghp_16C7e42F292c6912E7710c838347Ae178B4a"));
});

test("verified-live findings sort ahead of unverified ones", () => {
  const sorted = sortFindings([
    finding({ ruleId: "a", severity: "critical" }),
    finding({ ruleId: "b", severity: "low", verified: true }),
  ]);
  assert.strictEqual(sorted[0].ruleId, "b", "a live credential outranks an unverified critical");
});

test("json output carries a machine-readable summary", () => {
  const parsed = JSON.parse(render([finding({ verified: true })], "json", opts));
  assert.strictEqual(parsed.summary.total, 1);
  assert.strictEqual(parsed.summary.confirmedLive, 1);
  assert.strictEqual(parsed.findings[0].line, 7);
});

test("sarif output is valid 2.1.0 with one result per finding", () => {
  const parsed = JSON.parse(render([finding()], "sarif", opts));
  assert.strictEqual(parsed.version, "2.1.0");
  assert.strictEqual(parsed.runs[0].results.length, 1);
  assert.strictEqual(
    parsed.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri,
    "src/app.ts"
  );
  assert.strictEqual(parsed.runs[0].results[0].locations[0].physicalLocation.region.startLine, 7);
});

test("sarif escalates a verified-live finding to error level", () => {
  const parsed = JSON.parse(render([finding({ verified: true })], "sarif", opts));
  assert.strictEqual(parsed.runs[0].results[0].level, "error");
});

test("sarif marks entropy heuristics as note, not error", () => {
  const parsed = JSON.parse(
    render([finding({ confidence: "entropy-heuristic", severity: "medium" })], "sarif", opts)
  );
  assert.strictEqual(parsed.runs[0].results[0].level, "note");
});

test("sarif never embeds the raw secret", () => {
  const out = render([finding()], "sarif", opts);
  assert.ok(!out.includes("292c6912E7710c838347"));
});

test("empty result set renders a clean message", () => {
  assert.ok(render([], "text", opts).includes("no secrets found"));
});

suite("\nreport.ts — rebrand");

test("sarif reports the tool as SecretLoop", () => {
  const parsed = JSON.parse(render([finding()], "sarif", opts));
  assert.strictEqual(parsed.runs[0].tool.driver.name, "SecretLoop");
});

test("sarif keeps the pre-rebrand partialFingerprints key", () => {
  // GitHub code scanning keys alert identity off this field. Renaming it would
  // resurface every previously triaged alert as new, so it stays put.
  const parsed = JSON.parse(render([finding()], "sarif", opts));
  assert.deepStrictEqual(
    Object.keys(parsed.runs[0].results[0].partialFingerprints),
    ["secretguardFingerprint"]
  );
});

test("empty text report is branded SecretLoop", () => {
  assert.ok(render([], "text", opts).startsWith("SecretLoop:"));
});

finish();
