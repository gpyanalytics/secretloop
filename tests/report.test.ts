import { render, sortFindings } from "../src/report";
import { Finding } from "../src/scanner";
import { PKCS12_RULE_ID } from "../src/pkcs12";
import { test, suite, finish, assert } from "./harness";
import { readFileSync } from "fs";
import * as path from "path";

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

test("sarif names its fingerprint key for this product, and versions it", () => {
  // The name is a one-way door once alerts exist under it. It must not carry
  // the name of a product that never shipped, and the version suffix is what
  // lets a future algorithm change publish alongside rather than replace.
  const parsed = JSON.parse(render([finding()], "sarif", opts));
  assert.deepStrictEqual(
    Object.keys(parsed.runs[0].results[0].partialFingerprints),
    ["secretloopFingerprint/v2"]
  );
});

test("empty text report is branded SecretLoop", () => {
  assert.ok(render([], "text", opts).startsWith("SecretLoop:"));
});

suite("\nreport.ts — attribution");

test("each finding renders its own value, location and fingerprint", () => {
  // The one property this tool's output cannot get wrong. Rendering one
  // credential's value against another finding would send someone to rotate the
  // wrong key while the real one stays live.
  const out = render(
    [
      finding({
        ruleId: "github-token",
        value: "ghp_AAAAAAAAAAAAAAAAAAAA",
        file: "src/gh.ts",
        line: 11,
        fingerprint: "src/gh.ts:github-token:1111111111111111",
      }),
      finding({
        ruleId: "npm-token",
        value: "npm_BBBBBBBBBBBBBBBBBBBB",
        file: "src/pub.ts",
        line: 22,
        fingerprint: "src/pub.ts:npm-token:2222222222222222",
      }),
    ],
    "text",
    { redact: false, root: "/repo" }
  );
  const gh = out.slice(out.indexOf("github-token"), out.indexOf("npm-token"));
  const npm = out.slice(out.indexOf("npm-token"));
  assert.ok(gh.includes("ghp_AAAAAAAAAAAAAAAAAAAA"), "the GitHub block must carry the GitHub value");
  assert.ok(!gh.includes("npm_BBBBBBBBBBBBBBBBBBBB"), "and must not carry the npm one");
  assert.ok(gh.includes("src/gh.ts:11") && gh.includes("1111111111111111"));
  assert.ok(npm.includes("npm_BBBBBBBBBBBBBBBBBBBB") && !npm.includes("ghp_AAAAAAAAAAAAAAAAAAAA"));
  assert.ok(npm.includes("src/pub.ts:22") && npm.includes("2222222222222222"));
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
    "secretloopFingerprint/v2",
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
  assert.match(out, /1 needing a look/);
  assert.match(out, /1 dead/);
});

suite("\nreport.ts — merged rule ids");

test("json carries the rules that yielded", () => {
  const parsed = JSON.parse(
    render([finding({ alsoMatched: ["generic-api-key-assignment"] })], "json", opts)
  );
  assert.deepStrictEqual(parsed.findings[0].alsoMatched, ["generic-api-key-assignment"]);
});

test("json reports null rather than omitting the field when nothing yielded", () => {
  const parsed = JSON.parse(render([finding()], "json", opts));
  assert.strictEqual(parsed.findings[0].alsoMatched, null);
});

test("sarif carries them in properties", () => {
  const parsed = JSON.parse(
    render([finding({ alsoMatched: ["generic-api-key-assignment"] })], "sarif", opts)
  );
  assert.deepStrictEqual(parsed.runs[0].results[0].properties.alsoMatched, [
    "generic-api-key-assignment",
  ]);
});

test("the text report stays quiet about them", () => {
  // Corroboration is for a machine reading the output, not for someone
  // triaging a list of secrets.
  const out = render([finding({ alsoMatched: ["generic-api-key-assignment"] })], "text", opts);
  assert.doesNotMatch(out, /alsoMatched|generic-api-key-assignment/);
});

suite("\nreport.ts — the shape of the result comes first");

test("the text report opens with the summary, not with findings", () => {
  // On a real repo the trailing summary sits after hundreds of lines, so the
  // reader learns what they are looking at only by scrolling back up.
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
  const first = out.split("\n")[0];
  assert.match(first, /4 finding\(s\)/, `first line was: ${first}`);
  assert.match(first, /1 confirmed live/);
  assert.match(first, /1 needing a look/);
  assert.match(first, /1 unverified/);
  assert.match(first, /1 dead/);
});

test("the trailing summary is kept, and reads identically to the header", () => {
  const out = render([finding({ verifyStatus: "live" })], "text", opts);
  const lines = out.trimEnd().split("\n");
  const footer = lines.pop()!;
  assert.match(footer, /finding\(s\)/, "still useful after reading");
  // Both appear together on screen; describing the same numbers two ways reads
  // as two different results.
  assert.ok(lines[0].endsWith(footer), `header ${JSON.stringify(lines[0])} vs footer ${JSON.stringify(footer)}`);
});

test("the header names what was scanned when the caller knows", () => {
  const out = render([finding()], "text", { ...opts, scope: "31 commits" });
  assert.match(out.split("\n")[0], /Scanned 31 commits/);
});

test("without a scope the header is just the counts", () => {
  const out = render([finding()], "text", opts);
  assert.doesNotMatch(out.split("\n")[0], /Scanned/);
});

test("an empty result set is still a single clean line", () => {
  assert.strictEqual(render([], "text", opts), "SecretLoop: no secrets found.");
});

test("json and sarif are untouched by the header", () => {
  const json = JSON.parse(render([finding()], "json", { ...opts, scope: "31 commits" }));
  assert.strictEqual(json.tool, "secretloop");
  assert.strictEqual(json.findings.length, 1);
  const sarif = JSON.parse(render([finding()], "sarif", { ...opts, scope: "31 commits" }));
  assert.strictEqual(sarif.version, "2.1.0");
  assert.strictEqual(sarif.runs[0].results.length, 1);
});

suite("report.ts — a scan that found nothing still says what it looked at");

test("the scope survives the zero-finding path", () => {
  // The one case where the scope IS the message. Dropping it here is what let
  // `--path /does/not/exist` print a clean bill of health: nothing enumerated,
  // nothing scanned, "no secrets found."
  const out = render([], "text", { ...opts, scope: "412 file(s)" });
  assert.match(out, /412 file\(s\)/, "a clean scan must still report what it covered");
  assert.match(out, /no secrets found/i);
});

suite("\nreport.ts — same-value grouping in the text report");

// The text report folds occurrences of one credential into one entry: "N locations, same value". That sentence is a
// claim about the credential, so it may only be made when the occurrences really carry the same credential value.
const keystore = (file: string, digest: string): Finding =>
  finding({
    ruleId: PKCS12_RULE_ID,
    description: "PKCS#12 keystore containing private-key material",
    // What the detector reports in place of the keystore: a description, identical for any two keystores of one size.
    value: "PKCS#12 keystore, 2555 bytes, private-key material present",
    endIndex: 2555,
    line: 1,
    file,
    fingerprintStrategy: "context",
    fingerprint: `${file}:${PKCS12_RULE_ID}:${digest}`,
  });

test("two different keystores of the same size are not reported as the same value", () => {
  const out = render([keystore("a/client.p12", "1111111111111111"), keystore("b/client.p12", "2222222222222222")], "text", opts);
  assert.ok(!out.includes("same value"), "equal descriptions are not equal credentials; nothing here shows the keystores match");
  assert.strictEqual(out.split("(pkcs12-private-key)").length - 1, 2, "each keystore must be its own entry");
  const a = out.slice(out.indexOf("a/client.p12:1"), out.indexOf("b/client.p12:1"));
  assert.ok(a.includes("a/client.p12:pkcs12-private-key:1111111111111111"), "each entry carries its own fingerprint");
  assert.ok(!a.includes("2222222222222222"), "and not the other keystore's");
});

test("even byte-identical keystores are listed separately: the report has no keystore identity to compare", () => {
  // Same fingerprint digest on purpose. The report never derives a content identity for a keystore, so it does not
  // claim two of them match, whatever their digests say.
  const out = render([keystore("a/client.p12", "3333333333333333"), keystore("b/client.p12", "3333333333333333")], "text", opts);
  assert.ok(!out.includes("same value"));
  assert.strictEqual(out.split("(pkcs12-private-key)").length - 1, 2);
});

test("control: one credential in two files is still one entry, '2 locations, same value'", () => {
  const value = "ghp_Q7mK2xVb9RtL4nWz8YcP1sDf6HjA3uEgT5oN";
  const out = render(
    [
      finding({ value, file: "src/github-client.js", line: 2, fingerprint: "src/github-client.js:github-token:e8f3ee9fc6b4a606" }),
      finding({ value, file: "deploy/ci-settings.yaml", line: 3, fingerprint: "deploy/ci-settings.yaml:github-token:e8f3ee9fc6b4a606" }),
    ],
    "text",
    opts
  );
  assert.match(out, /2 locations, same value:/);
  assert.strictEqual(out.split("(github-token)").length - 1, 1, "one entry for one credential");
  assert.ok(out.includes("src/github-client.js:2") && out.includes("deploy/ci-settings.yaml:3"), "every location is listed");
});

test("control: different values whose masked forms are identical are not grouped", () => {
  // Same length, same first four and last four characters: both mask to ghp_********************T5oN.
  const one = "ghp_Q7mK2xVb9RtL4nWz8YcP1sDf6HjA3uEgT5oN";
  const two = "ghp_Zx9Lm3Qr7Tn1Wv5Yb2Kc8Hd4Jf6Ps0UgT5oN";
  const out = render([finding({ value: one, file: "a.js", line: 1 }), finding({ value: two, file: "b.js", line: 1 })], "text", opts);
  assert.strictEqual(out.split("ghp_********************T5oN").length - 1, 2, "the two masks really are identical");
  assert.ok(!out.includes("same value"), "a matching mask is not a matching credential");
});

test("control: different values whose fingerprint digests are identical are not grouped", () => {
  // Context-strategy fingerprints hash secret-free structure, so two different passwords on one host share a digest.
  const url = (password: string) => `postgres://app:${password}@db.internal:5432/app`;
  const out = render(
    [
      finding({ ruleId: "db-connection-string", value: url("Qm7vR2xKp9Lw4Tz8"), file: "a/app.env", line: 1, fingerprintStrategy: "context", fingerprint: "a/app.env:db-connection-string:b838750174e218f4" }),
      finding({ ruleId: "db-connection-string", value: url("Zx4nW8cV1bN6mQ3r"), file: "b/worker.env", line: 1, fingerprintStrategy: "context", fingerprint: "b/worker.env:db-connection-string:b838750174e218f4" }),
    ],
    "text",
    opts
  );
  assert.ok(!out.includes("same value"), "a matching fingerprint digest is not a matching credential");
});

test("control: one value under two different rules stays two entries", () => {
  const value = "ghp_Q7mK2xVb9RtL4nWz8YcP1sDf6HjA3uEgT5oN";
  const out = render([finding({ value, file: "a.js" }), finding({ ruleId: "generic-api-key", value, file: "b.js" })], "text", opts);
  assert.ok(!out.includes("same value"), "two rules are two different claims about the string");
});

suite("\nreport.ts — credential groups in the JSON report");

// The JSON report says which findings carry the same credential, so a consumer never has to compare values itself.
// These values are synthetic and match no provider format: no detector runs here, so none is needed.
interface JsonFinding { id: string; file: string | null; line: number; value: string; [key: string]: unknown }
interface JsonGroup { id: string; ruleId: string; findings: string[]; occurrences: number }
interface JsonReport {
  summary: Record<string, unknown>;
  findings: JsonFinding[];
  credentialGroups: JsonGroup[];
  [key: string]: unknown;
}

const VALUE_A = "fixture-value-A-0001";
const VALUE_B = "fixture-value-B-0001"; // same length, first four and last four as VALUE_A: the masks are identical
const VALUE_C = "fixture-value-C-0002";

const cred = (file: string, line: number, value: string, overrides: Partial<Finding> = {}): Finding =>
  finding({
    ruleId: "generic-password",
    description: "Hardcoded password",
    severity: "high",
    value,
    file,
    line,
    column: 1,
    startIndex: line * 100,
    endIndex: line * 100 + value.length,
    fingerprint: `${file}:generic-password:${String(line).padStart(16, "0")}`,
    ...overrides,
  });

const json = (findings: Finding[], options = opts): JsonReport => JSON.parse(render(findings, "json", options));

/** Every group member names a finding the report actually emits, and every finding id is unique. */
function assertReferencesResolve(report: JsonReport): void {
  const ids = report.findings.map((f) => f.id);
  assert.strictEqual(new Set(ids).size, ids.length, "finding ids are unique");
  for (const g of report.credentialGroups) {
    for (const member of g.findings) assert.ok(ids.includes(member), `${g.id} names ${member}, which the report does not emit`);
  }
}

const membersOf = (report: JsonReport, group: JsonGroup) =>
  group.findings.map((id) => report.findings.find((f) => f.id === id)!);

test("1. one credential in two files is one group of two findings", () => {
  const report = json([cred("config/dev.env", 3, VALUE_A), cred("src/settings.ts", 12, VALUE_A)]);
  assert.strictEqual(report.credentialGroups.length, 1);
  const [g] = report.credentialGroups;
  assert.strictEqual(g.id, "G1");
  assert.strictEqual(g.ruleId, "generic-password");
  assert.strictEqual(g.occurrences, 2);
  assert.deepStrictEqual(membersOf(report, g).map((f) => f.file), ["config/dev.env", "src/settings.ts"]);
  assertReferencesResolve(report);
});

test("2. one credential in three files is one group of three", () => {
  const report = json([cred("config/dev.env", 3, VALUE_A), cred("src/settings.ts", 12, VALUE_A), cred("deploy/app.yml", 5, VALUE_A)]);
  assert.strictEqual(report.credentialGroups.length, 1);
  assert.strictEqual(report.credentialGroups[0].occurrences, 3);
  assert.strictEqual(report.credentialGroups[0].findings.length, 3);
  assertReferencesResolve(report);
});

test("3. the same rule with different values is not grouped", () => {
  const report = json([cred("a.env", 1, VALUE_A), cred("b.env", 1, VALUE_C)]);
  assert.deepStrictEqual(report.credentialGroups, []);
});

test("4. the same value under different rules is not grouped", () => {
  const report = json([cred("a.env", 1, VALUE_A), cred("b.env", 1, VALUE_A, { ruleId: "generic-api-key" })]);
  assert.deepStrictEqual(report.credentialGroups, [], "two rules are two different claims about the string");
});

test("4b. the same source text matched under different encodings is not grouped", () => {
  const report = json([cred("a.env", 1, VALUE_A, { encoding: "base64" }), cred("b.env", 1, VALUE_A, { encoding: "hex" })]);
  assert.deepStrictEqual(report.credentialGroups, [], "a different transform is a different decoded credential");
});

test("5. different values with identical redacted displays are not grouped", () => {
  const report = json([cred("a.env", 1, VALUE_A), cred("b.env", 1, VALUE_B)]);
  assert.strictEqual(report.findings[0].value, report.findings[1].value, "the two masks really are identical");
  assert.deepStrictEqual(report.credentialGroups, [], "a matching mask is not a matching credential");
});

test("6. different PKCS#12 keystores of one displayed size are not grouped", () => {
  const report = json([keystore("a/client.p12", "1111111111111111"), keystore("b/client.p12", "2222222222222222")]);
  assert.deepStrictEqual(report.credentialGroups, [], "equal descriptions are not equal credentials");
});

test("7. findings with no reliable raw value are never grouped", () => {
  // A keystore's value is a description, even when the fingerprints agree; an empty value identifies nothing.
  const report = json([
    keystore("a/client.p12", "3333333333333333"),
    keystore("b/client.p12", "3333333333333333"),
    cred("a.env", 1, ""),
    cred("b.env", 1, ""),
  ]);
  assert.deepStrictEqual(report.credentialGroups, []);
});

test("8. a credential seen once has no group", () => {
  const report = json([cred("a.env", 1, VALUE_A), cred("b.env", 1, VALUE_C)]);
  assert.deepStrictEqual(report.credentialGroups, []);
  assert.deepStrictEqual(report.findings.map((f) => f.id), ["F1", "F2"], "ungrouped findings still carry an id");
});

test("9. a duplicated occurrence does not inflate a group or make one", () => {
  const once = cred("a.env", 1, VALUE_A);
  assert.deepStrictEqual(json([once, { ...once }]).credentialGroups, [], "one occurrence reported twice is not two");
  const report = json([once, { ...once }, cred("b.env", 4, VALUE_A)]);
  assert.strictEqual(report.credentialGroups.length, 1);
  assert.strictEqual(report.credentialGroups[0].occurrences, 2, "counts distinct occurrences, not findings");
  assert.strictEqual(report.credentialGroups[0].findings.length, 3, "every emitted finding of the credential is a member");
  assertReferencesResolve(report);
});

test("9b. one value twice on one line is two occurrences", () => {
  const report = json([cred("a.env", 1, VALUE_A), cred("a.env", 1, VALUE_A, { column: 30, startIndex: 129, endIndex: 149 })]);
  assert.strictEqual(report.credentialGroups.length, 1);
  assert.strictEqual(report.credentialGroups[0].occurrences, 2);
});

test("10. finding and group ids are deterministic, in emitted order", () => {
  const input = [cred("b.env", 1, VALUE_C), cred("a.env", 1, VALUE_A), cred("d.env", 1, VALUE_C), cred("c.env", 1, VALUE_A)];
  const first = render(input, "json", opts);
  assert.strictEqual(render(input, "json", opts), first, "the same input renders the same report");
  // Distinct files: the sort orders them fully, so reversing the input changes nothing. Findings on one line keep
  // the scanner's order, which is deterministic but not something this test reorders.
  assert.strictEqual(render([...input].reverse(), "json", opts), first, "the sort, not the input order, decides the ids");
  const report: JsonReport = JSON.parse(first);
  assert.deepStrictEqual(report.findings.map((f) => `${f.id}:${f.file}`), ["F1:a.env", "F2:b.env", "F3:c.env", "F4:d.env"]);
  assert.deepStrictEqual(
    report.credentialGroups.map((g) => `${g.id}:${g.findings.join(",")}`),
    ["G1:F1,F3", "G2:F2,F4"],
    "groups are numbered by where their first member appears"
  );
});

test("11. references follow the emitted order after sorting, and a filtered-out member leaves no orphan", () => {
  // The live finding sorts first, so it is F1 whatever its input position.
  const live = cred("z.env", 9, VALUE_A, { verifyStatus: "live" });
  const report = json([cred("a.env", 1, VALUE_A), cred("b.env", 1, VALUE_C), live]);
  assert.strictEqual(report.findings[0].file, "z.env");
  assert.strictEqual(report.findings[0].id, "F1");
  assert.deepStrictEqual(report.credentialGroups[0].findings, ["F1", "F2"]);
  assert.deepStrictEqual(membersOf(report, report.credentialGroups[0]).map((f) => f.file), ["z.env", "a.env"]);
  // What was removed before rendering (inline suppression, the allowlist, the baseline) is not in the report, so
  // the credential it shared with a reported finding is no longer a group.
  assert.deepStrictEqual(json([cred("a.env", 1, VALUE_A), cred("b.env", 1, VALUE_C)]).credentialGroups, []);
  assertReferencesResolve(report);
});

test("12. groups carry no value, no part of one, and no secret-derived identifier", () => {
  for (const redact of [true, false]) {
    const report = json([cred("a.env", 1, VALUE_A), cred("b.env", 1, VALUE_A)], { ...opts, redact });
    const groups = JSON.stringify(report.credentialGroups);
    for (const fragment of [VALUE_A, VALUE_A.slice(0, 4), VALUE_A.slice(-4), "fixture"]) {
      assert.ok(!groups.includes(fragment), `credentialGroups disclosed "${fragment}" (redact=${redact})`);
    }
    for (const g of report.credentialGroups) {
      assert.deepStrictEqual(Object.keys(g), ["id", "ruleId", "findings", "occurrences"], "a group holds nothing else");
      assert.match(g.id, /^G[1-9]\d*$/);
      for (const member of g.findings) assert.match(member, /^F[1-9]\d*$/);
    }
  }
  // Positional, not derived: changing the credential leaves every id unchanged.
  const one = json([cred("a.env", 1, VALUE_A), cred("b.env", 1, VALUE_A)]);
  const other = json([cred("a.env", 1, VALUE_C), cred("b.env", 1, VALUE_C)]);
  assert.deepStrictEqual(other.credentialGroups, one.credentialGroups);
  assert.deepStrictEqual(other.findings.map((f) => f.id), one.findings.map((f) => f.id));
});

test("13. every existing JSON field keeps its name, position and value", () => {
  const report = json([cred("a.env", 1, VALUE_A), cred("b.env", 1, VALUE_A)]);
  assert.deepStrictEqual(Object.keys(report), ["tool", "summary", "findings", "credentialGroups"], "additions come last");
  assert.deepStrictEqual(Object.keys(report.findings[0]), [
    "ruleId", "description", "severity", "confidence", "verifyStatus", "verifyReason", "verifyDetail",
    "file", "line", "commit", "fingerprint", "alsoMatched", "value", "id",
  ]);
  assert.deepStrictEqual(Object.keys(report.summary), [
    "total", "scope", "scannedCount", "scopeNoun", "confirmedLive", "bySeverity", "byLiveness",
    "credentialGroupCount", "groupedFindingCount",
  ]);
  assert.strictEqual(report.summary.total, 2, "total still counts findings, not groups");
  assert.strictEqual(report.findings.length, 2, "grouping does not merge findings");
  assert.strictEqual(report.summary.credentialGroupCount, 1);
  assert.strictEqual(report.summary.groupedFindingCount, 2);
  assert.strictEqual(report.findings[1].fingerprint, "b.env:generic-password:0000000000000001");
});

test("14. the text report still groups exactly as before and names no report-local id", () => {
  const out = render([cred("a.env", 1, VALUE_A), cred("b.env", 1, VALUE_A)], "text", opts);
  assert.match(out, /2 locations, same value:/);
  assert.ok(!/\b[FG]1\b/.test(out) && !out.includes("credentialGroups"), "ids belong to the JSON report only");
  assert.ok(!render([keystore("a/client.p12", "1"), keystore("b/client.p12", "2")], "text", opts).includes("same value"));
});

test("15. SARIF gains nothing, and the MCP server does not reach the JSON reporter", () => {
  const sarif = render([cred("a.env", 1, VALUE_A), cred("b.env", 1, VALUE_A)], "sarif", opts);
  assert.ok(!sarif.includes("credentialGroups") && !sarif.includes('"F1"') && !sarif.includes('"G1"'));
  const src = (name: string) => readFileSync(path.join(__dirname, "..", "src", name), "utf8");
  for (const name of ["mcp.ts", "mcp-core.ts"]) {
    assert.ok(!/from "\.\/report"|import\("\.\/report"\)/.test(src(name)), `${name} now imports the reporter`);
  }
});

test("16. an empty report has an empty group list and zero counts", () => {
  const report = json([]);
  assert.deepStrictEqual(report.findings, []);
  assert.deepStrictEqual(report.credentialGroups, [], "present and empty: grouping ran and found nothing");
  assert.strictEqual(report.summary.credentialGroupCount, 0);
  assert.strictEqual(report.summary.groupedFindingCount, 0);
});

suite("\nreport.ts — the text report shows a name, it never lets the name drive the terminal");

/*
 * A file name, and a matched value, are the repository's bytes, and the text report printed them raw. A name holding
 * ESC drove the terminal (colour, cursor, title), CR or a bidi override rewrote what was shown, and a newline printed
 * lines of its own -- a forged "[critical]" block indistinguishable from a real finding. Every such character is now
 * shown as a visible escape (`\x1b`, `\n`, `\u202e`), so the report keeps one line per thing it prints and the name
 * stays findable. JSON and SARIF keep the real bytes: they are data, escaped by their own formats.
 */
const HOSTILE: Array<[string, string]> = [
  ["esc\u001b[31mRED\u001b[0m.js", "esc\\x1b[31mRED\\x1b[0m.js"],
  ["osc\u001b]0;title\u0007.js", "osc\\x1b]0;title\\x07.js"],
  ["nl\n  [critical] FORGED (forged-rule)\n    x.js", "nl\\x0a  [critical] FORGED (forged-rule)\\x0a    x.js"],
  ["cr\rover.js", "cr\\x0dover.js"],
  ["tab\tname.js", "tab\\x09name.js"],
  ["del\u007f.js", "del\\x7f.js"],
  ["c1\u009b31m.js", "c1\\x9b31m.js"],
  ["rlo\u202eexe.js", "rlo\\u202eexe.js"],
  ["iso\u2066x\u2069.js", "iso\\u2066x\\u2069.js"],
  ["lrm\u200e.js", "lrm\\u200e.js"],
  ["alm\u061c.js", "alm\\u061c.js"],
  ["ls\u2028ps\u2029.js", "ls\\u2028ps\\u2029.js"],
  ["lone\ud800.js", "lone\\ud800.js"],
];
// Anything a terminal acts on, other than the line breaks the report itself writes.
const ACTIVE = /[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069\u2028\u2029]|[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;

function textFor(file: string, extra: Partial<Finding> = {}): string {
  return render([finding({ file, fingerprint: `${file}:github-token:deadbeefdeadbeef`, ...extra })], "text", opts);
}

for (const [name, shown] of HOSTILE) {
  test(`a name shown as ${shown} takes as many lines as an ordinary name`, () => {
    const out = textFor(name);
    assert.ok(!ACTIVE.test(out), `an active character reached the text report for ${shown}`);
    assert.strictEqual(out.split("\n").length, textFor("plain.js").split("\n").length, "the name printed lines of its own");
    assert.ok(out.includes(`  ${shown}:7\n`), `location line for ${shown}`);
    assert.ok(out.includes(`fingerprint: ${shown}:github-token:deadbeefdeadbeef`), "fingerprint line");
  });
}

test("no forged block survives: the only [critical] line is the real one", () => {
  const out = textFor("nl\n  [critical] FORGED (forged-rule)\n    x.js");
  assert.deepStrictEqual(out.split("\n").filter((l) => /^\s*\[critical\]/.test(l)), ["  [critical] GitHub Personal Access Token (github-token)"]);
});

test("a history location and every member of a same-value group are shown the same way", () => {
  const a = finding({ file: "a\u001b[2Jx.js", commit: "0123456789abcdef", fingerprint: "a\u001b[2Jx.js:github-token:1111111111111111" });
  const b = finding({ file: "b\nFORGED.js", fingerprint: "b\nFORGED.js:github-token:2222222222222222" });
  const out = render([a, b], "text", opts);
  assert.ok(!ACTIVE.test(out), JSON.stringify(out));
  assert.ok(out.includes("a\\x1b[2Jx.js:7 (commit 01234567)"));
  assert.ok(out.includes("b\\x0aFORGED.js:7"));
  assert.ok(!out.split("\n").some((l) => l.startsWith("FORGED")), "the newline printed a line");
});

test("a confirmed-dead entry shows its location the same way", () => {
  const out = render([finding({ file: "d\u001b[8m.js", verifyStatus: "dead" })], "text", opts);
  assert.ok(!ACTIVE.test(out), JSON.stringify(out));
  assert.ok(out.includes("d\\x1b[8m.js:7"));
});

test("a value and a verification detail are shown the same way, redacted or not", () => {
  const value = "ghp_\u001b[31m6C7e42F292c6912E7710c838347Ae178B\u001b";
  for (const redact of [true, false]) {
    const out = render([finding({ value, verifyDetail: "detail\u001b]0;x\u0007\nFORGED" })], "text", { ...opts, redact });
    assert.ok(!ACTIVE.test(out), `redact=${redact}: ${JSON.stringify(out)}`);
    assert.ok(!out.split("\n").some((l) => l.startsWith("FORGED")), "the detail printed a line");
  }
  assert.ok(render([finding({ value })], "text", { ...opts, redact: false }).includes("ghp_\\x1b[31m6C7e42F292c6912E7710c838347Ae178B\\x1b"));
});

test("ordinary names, including non-ASCII, spaces, quotes and backslashes, are shown exactly as they are", () => {
  for (const name of ["src/app.ts", "café/naïve.js", "dir name/a b.js", 'quo"te.js', "back\\slash.js", "日本/設定.js", "emoji😀.js"]) {
    const out = textFor(name);
    assert.ok(out.includes(`  ${name}:7\n`), `${JSON.stringify(name)}: ${JSON.stringify(out)}`);
    assert.ok(out.includes(`fingerprint: ${name}:github-token:deadbeefdeadbeef`));
  }
});

test("JSON and SARIF keep the real name; only the text report escapes it", () => {
  const name = "esc\u001b[31mRED\u001b[0m.js";
  const f = finding({ file: name, fingerprint: `${name}:github-token:deadbeefdeadbeef` });
  const j = JSON.parse(render([f], "json", opts));
  assert.strictEqual(j.findings[0].file, name);
  assert.strictEqual(j.findings[0].fingerprint, `${name}:github-token:deadbeefdeadbeef`);
  const s = JSON.parse(render([f], "sarif", opts));
  assert.strictEqual(s.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, "esc%1B%5B31mRED%1B%5B0m.js");
  assert.strictEqual(s.runs[0].results[0].partialFingerprints["secretloopFingerprint/v2"], `${name}:github-token:deadbeefdeadbeef`);
});

finish();
