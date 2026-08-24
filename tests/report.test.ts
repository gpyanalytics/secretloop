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
    finding({ ruleId: "b", severity: "low", verifyStatus: "live" }),
  ]);
  assert.strictEqual(sorted[0].ruleId, "b", "a live credential outranks an unverified critical");
});

test("a dead credential sorts below everything still in question", () => {
  const sorted = sortFindings([
    finding({ ruleId: "dead", severity: "critical", verifyStatus: "dead" }),
    finding({ ruleId: "unchecked", severity: "low" }),
    finding({ ruleId: "unknown", severity: "low", verifyStatus: "unknown", verifyReason: "network" }),
  ]);
  assert.deepStrictEqual(
    sorted.map((f) => f.ruleId),
    ["unknown", "unchecked", "dead"],
    "proven-dead is the least urgent thing in the report, whatever its severity"
  );
});

test("json output carries a machine-readable summary", () => {
  const parsed = JSON.parse(render([finding({ verifyStatus: "live" })], "json", opts));
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
  const parsed = JSON.parse(render([finding({ verifyStatus: "live" })], "sarif", opts));
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

suite("\nreport.ts — liveness in JSON");

test("json reports the liveness tri-state, not a boolean", () => {
  const parsed = JSON.parse(
    render([finding({ verifyStatus: "unknown", verifyReason: "provider-refused", verifyDetail: "d" })], "json", opts)
  );
  const f = parsed.findings[0];
  assert.strictEqual(f.verifyStatus, "unknown");
  assert.strictEqual(f.verifyReason, "provider-refused");
  assert.strictEqual(f.verifyDetail, "d");
});

test("json no longer emits the verified boolean", () => {
  // It could not express "unknown", which is how a 403 came to read as revoked.
  const parsed = JSON.parse(render([finding({ verifyStatus: "unknown", verifyReason: "network" })], "json", opts));
  assert.ok(!("verified" in parsed.findings[0]), "the ambiguous boolean must be gone, not merely unset");
});

test("json distinguishes never-checked from checked-and-unknown", () => {
  const parsed = JSON.parse(render([finding()], "json", opts));
  assert.strictEqual(parsed.findings[0].verifyStatus, null, "null means no verification pass ran");
  assert.strictEqual(parsed.findings[0].verifyReason, null);
});

test("json summary counts every liveness state", () => {
  const parsed = JSON.parse(
    render(
      [
        finding({ ruleId: "a", verifyStatus: "live" }),
        finding({ ruleId: "b", verifyStatus: "dead" }),
        finding({ ruleId: "c", verifyStatus: "unknown", verifyReason: "network" }),
        finding({ ruleId: "d" }),
      ],
      "json",
      opts
    )
  );
  assert.deepStrictEqual(parsed.summary.byLiveness, { live: 1, dead: 1, unknown: 1, unchecked: 1 });
  assert.strictEqual(parsed.summary.confirmedLive, 1);
});

suite("\nreport.ts — liveness in SARIF");

test("sarif carries status and reason in properties", () => {
  const parsed = JSON.parse(
    render([finding({ verifyStatus: "unknown", verifyReason: "provider-refused", verifyDetail: "why" })], "sarif", opts)
  );
  const result = parsed.runs[0].results[0];
  assert.strictEqual(result.properties.verificationStatus, "unknown");
  assert.strictEqual(result.properties.verificationReason, "provider-refused");
  assert.strictEqual(result.properties.verificationDetail, "why");
});

test("sarif keeps partialFingerprints reserved for alert identity", () => {
  const parsed = JSON.parse(
    render([finding({ verifyStatus: "unknown", verifyReason: "network" })], "sarif", opts)
  );
  assert.deepStrictEqual(Object.keys(parsed.runs[0].results[0].partialFingerprints), [
    "secretguardFingerprint",
  ]);
});

test("sarif drops a proven-dead credential to note", () => {
  const parsed = JSON.parse(render([finding({ verifyStatus: "dead" })], "sarif", opts));
  assert.strictEqual(
    parsed.runs[0].results[0].level,
    "note",
    "still recorded — it is a secret in source — but it must not block a build"
  );
});

test("sarif keeps a refused check at error, since the provider recognised the credential", () => {
  // A garbage token 401s. A 403 means the provider evaluated it and declined,
  // which leans live — and it is the case only a human can settle.
  const parsed = JSON.parse(
    render([finding({ severity: "low", verifyStatus: "unknown", verifyReason: "provider-refused" })], "sarif", opts)
  );
  assert.strictEqual(parsed.runs[0].results[0].level, "error");
});

test("sarif leaves other unknowns at their format-based level", () => {
  // A network failure taught us nothing, so the finding is worth exactly what
  // its format was worth before the check ran.
  const unreachable = JSON.parse(
    render([finding({ severity: "medium", verifyStatus: "unknown", verifyReason: "network" })], "sarif", opts)
  );
  assert.strictEqual(unreachable.runs[0].results[0].level, "warning");
  const critical = JSON.parse(
    render([finding({ severity: "critical", verifyStatus: "unknown", verifyReason: "network" })], "sarif", opts)
  );
  assert.strictEqual(critical.runs[0].results[0].level, "error");
});

suite("\nreport.ts — text sections");

test("text separates live, needs-a-look, unverified and dead", () => {
  const out = render(
    [
      finding({ ruleId: "live-one", verifyStatus: "live" }),
      finding({ ruleId: "refused", verifyStatus: "unknown", verifyReason: "provider-refused" }),
      finding({ ruleId: "plain" }),
      finding({ ruleId: "gone", verifyStatus: "dead" }),
    ],
    "text",
    opts
  );
  assert.match(out, /CONFIRMED LIVE \(1\)/);
  assert.match(out, /NEEDS A LOOK \(1\)/);
  assert.match(out, /UNVERIFIED \(1\)/);
  assert.match(out, /CONFIRMED DEAD \(1\)/);
});

test("needs-a-look groups by remedy, not by provider", () => {
  const out = render(
    [
      finding({ ruleId: "a", verifyStatus: "unknown", verifyReason: "network" }),
      finding({ ruleId: "b", verifyStatus: "unknown", verifyReason: "network" }),
      finding({ ruleId: "c", verifyStatus: "unknown", verifyReason: "provider-refused" }),
    ],
    "text",
    opts
  );
  assert.match(out, /could not reach the provider \(2\)/i);
  assert.match(out, /refused the check \(1\)/i);
  // The two remedies are different actions and must read differently.
  assert.match(out, /egress|connectivity|network/i);
  assert.match(out, /inspect|check .* directly|look at/i);
});

test("a dead credential is reported compactly, without a detail block", () => {
  const out = render([finding({ ruleId: "gone", verifyStatus: "dead", verifyDetail: "revoked upstream" })], "text", opts);
  assert.match(out, /CONFIRMED DEAD \(1\)/);
  assert.ok(!out.includes("revoked upstream"), "a dead finding should not compete for attention");
  assert.match(out, /still in your source|remove/i, "it is still a secret in the repository");
});

test("the text summary accounts for every finding", () => {
  const out = render(
    [
      finding({ ruleId: "a", verifyStatus: "live" }),
      finding({ ruleId: "b", verifyStatus: "unknown", verifyReason: "network" }),
      finding({ ruleId: "c" }),
      finding({ ruleId: "d", verifyStatus: "dead" }),
    ],
    "text",
    opts
  );
  assert.match(out, /4 finding\(s\)/);
  assert.match(out, /1 confirmed live/);
  assert.match(out, /1 needs a look/);
  assert.match(out, /1 dead/);
});

finish();
