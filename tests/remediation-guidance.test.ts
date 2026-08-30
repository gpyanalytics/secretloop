import "./stubs/install-vscode";
import { test, suite, finish, assert } from "./harness";
import { render, REMEDIATION_NOTE } from "../src/report";
import { Finding } from "../src/scanner";
import { offersEnvExtraction, offersRotation } from "../src/extension";
import { positiveSamples } from "./fixtures";

/**
 * 0.1.2 — remediation guidance, and the fixture-awareness that keeps it honest.
 *
 * SecretLoop could already move a secret to `.env` from the editor lightbulb,
 * but no CLI, JSON or SARIF surface ever said so: someone running it in CI saw
 * a finding and no suggestion of what to do about it.
 *
 * The guidance is conditional on purpose. 0.1.2's fixture fix means
 * format-match findings in test paths now report -- correctly -- and telling
 * someone to move `YOUR_BROWSER_API_KEY` out of a fixture and into `.env` is
 * advice that is simply wrong. The finding still reports; it just carries no
 * relocation advice.
 */

const RAW = positiveSamples["github-token"];

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: "github-token",
    description: "GitHub Personal Access Token",
    value: RAW,
    startIndex: 0,
    endIndex: RAW.length,
    confidence: "format-match",
    severity: "critical",
    line: 3,
    file: "src/app.ts",
    fingerprint: "src/app.ts:github-token:1111111111111111",
    ...overrides,
  };
}

const opts = { redact: true, root: "/repo" };
const FIXTURE_FILE = "tests/fixtures/creds.ts";

// ---------------------------------------------------------------------------
suite("0.1.2 — remediation guidance is present on a genuine finding");

/**
 * A guard on the guards.
 *
 * The SARIF presence test below passed in RED before this existed: the export
 * was undefined and so was the SARIF field, so strictEqual(undefined, undefined)
 * held and proved nothing. Every assertion in this file reads REMEDIATION_NOTE,
 * so if it is ever not a real sentence they all become vacuous together.
 */
test("preflight: the guidance constant is a real sentence about environment variables", () => {
  assert.strictEqual(typeof REMEDIATION_NOTE, "string");
  assert.ok(REMEDIATION_NOTE.length > 20, "the guidance constant is empty or a stub");
  assert.match(REMEDIATION_NOTE, /environment variable/);
});

test("the text report tells you to move it to an environment variable", () => {
  const text = render([finding()], "text", opts);
  assert.ok(
    text.includes(REMEDIATION_NOTE),
    `guidance missing from the text report:\n${text}`
  );
});

test("SARIF carries the guidance per result, in the properties bag", () => {
  const sarif = JSON.parse(render([finding()], "sarif", opts));
  const remediation = sarif.runs[0].results[0].properties.remediation;
  // Asserted as a string first. Comparing straight to REMEDIATION_NOTE let this
  // pass in RED, when both sides were undefined.
  assert.strictEqual(typeof remediation, "string", "SARIF result carries no remediation string");
  assert.strictEqual(remediation, REMEDIATION_NOTE);
});

test("the guidance reaches unverified and unknown findings, not only live ones", () => {
  for (const f of [
    finding({ verifyStatus: "unknown", verifyReason: "no-verifier" }),
    finding({ confidence: "verified-live", verifyStatus: "live" }),
    finding({ confidence: "entropy-heuristic", ruleId: "generic-high-entropy" }),
  ]) {
    assert.ok(render([f], "text", opts).includes(REMEDIATION_NOTE), `missing for ${f.ruleId}/${f.verifyStatus}`);
  }
});

// ---------------------------------------------------------------------------
suite("0.1.2 — and absent on a fixture-path finding, which still reports");

test("a fixture-path finding reports but carries no relocation advice", () => {
  // BOTH halves in one test on purpose. Asserting only the absence of the
  // guidance would pass just as well if the finding had stopped reporting --
  // which is the exact regression 0.1.2's safety fix exists to prevent.
  const text = render([finding({ file: FIXTURE_FILE })], "text", opts);
  assert.ok(text.includes("GitHub Personal Access Token"), `the finding stopped reporting:\n${text}`);
  assert.ok(text.includes(FIXTURE_FILE), `the location stopped reporting:\n${text}`);
  assert.ok(!text.includes(REMEDIATION_NOTE), `fixture finding was told to move to .env:\n${text}`);
});

test("SARIF keeps the fixture result and nulls only its remediation", () => {
  const sarif = JSON.parse(render([finding({ file: FIXTURE_FILE })], "sarif", opts));
  const results = sarif.runs[0].results;
  assert.strictEqual(results.length, 1, "the fixture result was dropped from SARIF");
  assert.strictEqual(results[0].properties.remediation, null);
  assert.strictEqual(
    results[0].partialFingerprints["secretloopFingerprint/v2"],
    "src/app.ts:github-token:1111111111111111"
  );
});

test("a value in both src and tests keeps the advice", () => {
  // Grouped by value: one credential in two places is one entry. If any
  // occurrence is real source, the advice applies.
  const group = [
    finding({ file: "src/app.ts", fingerprint: "src/app.ts:github-token:1111111111111111" }),
    finding({ file: FIXTURE_FILE, fingerprint: "tests/fixtures/creds.ts:github-token:2222222222222222" }),
  ];
  const text = render(group, "text", opts);
  assert.ok(text.includes(REMEDIATION_NOTE), `a mixed group lost the advice:\n${text}`);
});

test("a group entirely inside fixture paths loses the advice", () => {
  const group = [
    finding({ file: "tests/fixtures/a.ts", fingerprint: "tests/fixtures/a.ts:github-token:1111111111111111" }),
    finding({ file: "test/b.ts", fingerprint: "test/b.ts:github-token:2222222222222222" }),
  ];
  const text = render(group, "text", opts);
  assert.ok(text.includes("GitHub Personal Access Token"), "the group stopped reporting");
  assert.ok(!text.includes(REMEDIATION_NOTE), `an all-fixture group kept the advice:\n${text}`);
});

test("a finding with no file at all is treated as non-fixture and keeps the advice", () => {
  // scanText over a raw stream produces findings with no path. The predicate
  // must not throw on undefined, and "unknown" is not "fixture".
  const text = render([finding({ file: undefined, fingerprint: undefined })], "text", opts);
  assert.ok(text.includes(REMEDIATION_NOTE));
});

// ---------------------------------------------------------------------------
suite("0.1.2 — the guidance never carries the credential");

test("the raw value appears in no guidance text, in any format, while redaction is on", () => {
  // The gap the audit found: every existing test asserted the clipboard did not
  // get the value, and none asserted the message text did not.
  for (const format of ["text", "sarif"] as const) {
    for (const f of [finding(), finding({ file: FIXTURE_FILE })]) {
      const out = render([f], format, opts);
      assert.ok(!out.includes(RAW), `the raw credential leaked into the ${format} report`);
    }
  }
  // And the constant itself cannot template a value in.
  assert.ok(!/\$\{|%s/.test(REMEDIATION_NOTE), "the guidance string interpolates something");
});

test("the dead section says remove, not relocate", () => {
  const text = render([finding({ verifyStatus: "dead", confidence: "verified-live" })], "text", opts);
  assert.match(text, /still in your source\. Remove them\./);
  assert.ok(!text.includes(REMEDIATION_NOTE), "a dead credential was told to move to .env");
});

// ---------------------------------------------------------------------------
suite("0.1.2 — SARIF identity is untouched");

test("result identity, fingerprints, tags and security-severity are unchanged", () => {
  const findings = [
    finding({ file: "src/a.ts", fingerprint: "src/a.ts:github-token:1111111111111111" }),
    finding({ file: FIXTURE_FILE, fingerprint: "tests/fixtures/creds.ts:github-token:2222222222222222" }),
  ];
  const parsed = JSON.parse(render(findings, "sarif", opts));
  const run = parsed.runs[0];

  assert.strictEqual(parsed.version, "2.1.0");
  assert.strictEqual(run.tool.driver.name, "SecretLoop");
  assert.strictEqual(run.results.length, 2, "grouping or fixture logic leaked into SARIF");
  assert.deepStrictEqual(
    run.results.map((r: any) => r.partialFingerprints["secretloopFingerprint/v2"]),
    findings.map((f) => f.fingerprint)
  );
  assert.deepStrictEqual(run.results.map((r: any) => r.ruleId), ["github-token", "github-token"]);
  assert.deepStrictEqual(Object.keys(run.results[0].partialFingerprints), ["secretloopFingerprint/v2"]);

  // Rule metadata must NOT become scan-dependent -- that is why the guidance is
  // per result rather than a rule-level `help`.
  const rule = run.tool.driver.rules[0];
  assert.deepStrictEqual(rule.properties.tags, ["security", "secret"]);
  assert.ok(typeof rule.properties["security-severity"] === "string" || typeof rule.properties["security-severity"] === "number");
  assert.ok(!("help" in rule), "rule-level help was added; guidance belongs on the result");
  assert.deepStrictEqual(Object.keys(rule).sort(), ["defaultConfiguration", "id", "name", "properties", "shortDescription"]);
});

test("remediation is the only key added to result properties", () => {
  const parsed = JSON.parse(render([finding()], "sarif", opts));
  assert.deepStrictEqual(Object.keys(parsed.runs[0].results[0].properties).sort(), [
    "alsoMatched",
    "remediation",
    "verificationDetail",
    "verificationReason",
    "verificationStatus",
  ]);
});

// ---------------------------------------------------------------------------
suite("0.1.2 — the editor withholds only the .env quick-fix");

test("the .env action is offered on real source and withheld in fixture paths", () => {
  assert.strictEqual(offersEnvExtraction(finding()), true);
  assert.strictEqual(offersEnvExtraction(finding({ file: FIXTURE_FILE })), false);
  assert.strictEqual(offersEnvExtraction(finding({ file: "test/x.ts" })), false);
  assert.strictEqual(offersEnvExtraction(finding({ file: undefined })), true);
});

test("rotation is NOT withheld in a fixture path", () => {
  // The case 0.1.2 exists for: a credential that verified LIVE, in a test file,
  // is the most dangerous finding this tool produces. Withholding its provider
  // path would be a softer version of the blindness bug -- visible, unfixable.
  const live = finding({ file: FIXTURE_FILE, confidence: "verified-live", verifyStatus: "live" });
  assert.strictEqual(offersRotation(live), true, "rotate was withheld on a live fixture-path credential");
});
finish();
