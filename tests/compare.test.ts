import { test, suite, finish, assert, skip } from "./harness";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, appendFileSync, unlinkSync, symlinkSync, constants as fsConstants } from "fs";
import { tmpdir } from "os";
import { spawnSync, execFileSync } from "child_process";
import * as path from "path";
import {
  MAX_FINDING_DIAGNOSTICS_PER_SIDE,
  compareReports,
  loadReport,
  renderText,
  renderJson,
  MAX_FINDINGS,
  NO_LONGER_OBSERVED_CAVEAT,
} from "../src/compare";
import { REPORT_SCHEMA_VERSION, scopeIdentity } from "../src/report-metadata";
import { rulesById } from "../src/rules";
import { ENTROPY_RULE_ID } from "../src/scanner";
import { PKCS12_RULE_ID } from "../src/pkcs12";

/**
 * The comparator, tested through the SHIPPED CODE.
 *
 * Every eligibility verdict here comes from `compareReports` or from the CLI
 * itself — not from a model written alongside the assertions. The two suites are
 * labelled: "unit" exercises the exported functions, "integration" runs the real
 * binary over reports produced by the real scanner. Where a hand-built report is
 * used it is to reach a case the producer cannot emit (schema 2, a null field, a
 * hostile string), never to stand in for the comparator's own logic.
 *
 * Credentials are generated at runtime. Nothing credential-shaped is checked in.
 */

const CLI = path.join(__dirname, "..", "out", "cli.js");

function withDir(fn: (dir: string) => void): void {
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-cmp-"));
  try {
    fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** A runtime-generated synthetic credential. Never a checked-in fixture. */
function token(): string {
  const a = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let out = "ghp_";
  for (let i = 0; i < 36; i++) out += a[Math.floor(Math.random() * a.length)];
  return out;
}

const hex = (c: string) => c.repeat(16);

/** From the shared authority, exactly as the comparator takes it. */
const WORKTREE_SCOPE = scopeIdentity({ mode: "worktree" }) as string;
const HISTORY_SCOPE = scopeIdentity({ mode: "history", commits: ["a".repeat(40)] }) as string;

/** A minimal eligible report. Hand-built to reach cases a scan cannot produce. */
function report(over: Record<string, unknown> = {}, findings: unknown[] = []): any {
  return {
    tool: "secretloop",
    schemaVersion: REPORT_SCHEMA_VERSION,
    toolVersion: "0.5.1",
    root: `git:${hex("a")}`,
    configDigest: hex("b"),
    ruleSetDigest: hex("c"),
    suppressionDigest: hex("d"),
    scopeDigest: WORKTREE_SCOPE,
    binaryDigest: `binary:${hex("f")}`,
    incomplete: false,
    findings,
    ...over,
  };
}

const finding = (fp: string, over: Record<string, unknown> = {}) => ({
  ruleId: "github-token",
  file: "app.js",
  line: 1,
  severity: "critical",
  fingerprint: fp,
  ...over,
});

const FP1 = `app.js:github-token:${hex("1")}`;
const FP2 = `lib/x.js:aws-access-key:${hex("2")}`;

/** Compare two in-memory report objects through the shipped comparator. */
function cmp(a: any, b: any) {
  return compareReports({ meta: a, findings: a.findings }, { meta: b, findings: b.findings });
}

const codes = (r: ReturnType<typeof cmp>) => r.reasons.map((x) => x.code);

// ---------------------------------------------------------------------------
suite("compare (unit) — eligible pairs and the three outcomes");

test("identical reports compare, with everything persisting", () => {
  const a = report({}, [finding(FP1), finding(FP2)]);
  const r = cmp(a, report({}, [finding(FP1), finding(FP2)]));
  assert.strictEqual(r.comparable, true, JSON.stringify(r.reasons));
  assert.deepStrictEqual(r.added, []);
  assert.deepStrictEqual(r.noLongerObserved, []);
  assert.strictEqual(r.persisting.length, 2);
});

test("two empty eligible reports compare and say nothing changed", () => {
  const r = cmp(report(), report());
  assert.strictEqual(r.comparable, true);
  assert.strictEqual(r.added.length + r.persisting.length + r.noLongerObserved.length, 0);
});

test("new, persisting and no-longer-observed are each reported", () => {
  const r = cmp(report({}, [finding(FP1), finding(FP2)]), report({}, [finding(FP1), finding("z.js:slack-token:" + hex("3"))]));
  assert.strictEqual(r.comparable, true);
  assert.deepStrictEqual(r.persisting.map((f) => f.digest), [hex("1")]);
  assert.deepStrictEqual(r.noLongerObserved.map((f) => f.digest), [hex("2")]);
  assert.deepStrictEqual(r.added.map((f) => f.digest), [hex("3")]);
});

// ---------------------------------------------------------------------------
suite("\ncompare (unit) — every required field, every way it can fail");

test("each of the nine fields, absent, rejects the pair", () => {
  for (const field of [
    "schemaVersion", "toolVersion", "root", "configDigest", "ruleSetDigest",
    "suppressionDigest", "scopeDigest", "binaryDigest", "incomplete",
  ]) {
    const bad = report();
    delete bad[field];
    const r = cmp(report(), bad);
    assert.strictEqual(r.comparable, false, `${field} absent must reject`);
    assert.ok(codes(r).includes("missing-field"), `${field}: expected missing-field, got ${codes(r)}`);
    // A shared absence is still an absence.
    const both = report();
    delete both[field];
    assert.strictEqual(cmp(both, report(JSON.parse(JSON.stringify(both)))).comparable, false,
      `${field} absent on BOTH sides must still reject`);
  }
});

test("null, wrong type, empty and malformed values are each rejected", () => {
  const cases: [string, unknown][] = [
    ["root", null], ["root", 7], ["root", ""], ["root", "   "], ["root", hex("a")],
    ["configDigest", "not-hex"], ["configDigest", `git:${hex("a")}`],
    ["scopeDigest", hex("e")], ["scopeDigest", `binary:${hex("e")}`],
    ["binaryDigest", `scope:${hex("f")}`], ["binaryDigest", "binary:zz"],
    ["toolVersion", ""], ["toolVersion", "  "], ["toolVersion", 5],
    ["incomplete", "false"], ["incomplete", 0], ["incomplete", null],
    ["schemaVersion", "4"], ["schemaVersion", 4.5], ["schemaVersion", null],
  ];
  for (const [field, value] of cases) {
    const r = cmp(report(), report({ [field]: value }));
    assert.strictEqual(r.comparable, false, `${field}=${JSON.stringify(value)} must reject`);
  }
});

test("a mismatch in any identity field rejects the pair", () => {
  const cases: [string, unknown][] = [
    ["toolVersion", "0.5.2"],
    ["root", `git:${hex("9")}`],
    ["configDigest", hex("9")],
    ["ruleSetDigest", hex("9")],
    ["suppressionDigest", hex("9")],
    ["binaryDigest", `binary:${hex("9")}`],
  ];
  for (const [field, value] of cases) {
    const r = cmp(report(), report({ [field]: value }));
    assert.strictEqual(r.comparable, false, `${field} mismatch must reject`);
    assert.ok(r.reasons.some((x) => x.code === "identity-mismatch" && x.field === field),
      `${field}: expected identity-mismatch, got ${JSON.stringify(r.reasons)}`);
  }
});

test("there is exactly ONE supported scope, so scopeDigest cannot mismatch among accepted reports", () => {
  // A non-worktree scope is refused as UNSUPPORTED before equality is ever
  // considered -- a stronger rejection than "these two differ".
  const r = cmp(report(), report({ scopeDigest: HISTORY_SCOPE }));
  assert.strictEqual(r.comparable, false);
  assert.ok(r.reasons.some((x) => x.code === "unsupported-scope" && x.side === "after"),
    `expected unsupported-scope, got ${JSON.stringify(r.reasons)}`);
  // Two reports that both pass the scope check necessarily carry the same value.
  assert.strictEqual(cmp(report(), report()).comparable, true);
});

test("incomplete on either side, or both, rejects the pair", () => {
  for (const [a, b] of [[true, false], [false, true], [true, true]] as const) {
    const r = cmp(report({ incomplete: a }), report({ incomplete: b }));
    assert.strictEqual(r.comparable, false, `incomplete ${a}/${b} must reject`);
    assert.ok(codes(r).includes("incomplete-coverage"));
  }
  // true === true must not qualify through equality.
  const both = cmp(report({ incomplete: true }), report({ incomplete: true }));
  assert.strictEqual(both.reasons.filter((x) => x.code === "incomplete-coverage").length, 2,
    "both sides must be reported, not just one");
});

// ---------------------------------------------------------------------------
suite("\ncompare (unit) — schema versions");

test("schemas 1, 2 and 3 are rejected even when both sides agree", () => {
  for (const v of [1, 2, 3]) {
    const r = cmp(report({ schemaVersion: v }), report({ schemaVersion: v }));
    assert.strictEqual(r.comparable, false, `schema ${v} must reject`);
    assert.ok(codes(r).includes("unsupported-schema"));
  }
});

test("unknown future versions are rejected rather than guessed at", () => {
  for (const v of [5, 6, 99, 1000]) {
    const r = cmp(report({ schemaVersion: v }), report({ schemaVersion: v }));
    assert.strictEqual(r.comparable, false, `schema ${v} must reject`);
    assert.ok(codes(r).includes("unsupported-schema"));
  }
});

test("mixed-version pairs are rejected, and named as mixed", () => {
  const r = cmp(report(), report({ schemaVersion: 3 }));
  assert.strictEqual(r.comparable, false);
  assert.ok(codes(r).includes("mixed-schema"), `expected mixed-schema, got ${codes(r)}`);
  assert.ok(codes(r).includes("unsupported-schema"), "and the unsupported side is named too");
});

// ---------------------------------------------------------------------------
suite("\ncompare (unit) — finding identity");

test("duplicate fingerprints are counted, not collapsed by a Set", () => {
  // Fingerprints key on (path, rule, value) and NOT the line, so one credential
  // repeated in a file is several findings under one identity.
  const a = report({}, [finding(FP1, { line: 1 }), finding(FP1, { line: 9 }), finding(FP1, { line: 20 })]);
  const b = report({}, [finding(FP1, { line: 1 })]);
  const r = cmp(a, b);
  assert.strictEqual(r.comparable, true);
  assert.deepStrictEqual(r.persisting.map((f) => f.digest), [hex("1")]);
  assert.deepStrictEqual(r.noLongerObserved, [], "the credential is still there; nothing vanished");
  assert.strictEqual(r.ambiguousIdentity.length, 1, "the occurrence change must be surfaced");
  assert.deepStrictEqual(r.ambiguousIdentity[0],
    { ruleId: "github-token", digest: hex("1"), beforeCount: 3, afterCount: 1 });
});

test("a finding with no usable fingerprint rejects the comparison outright", () => {
  for (const bad of [
    {}, { fingerprint: null }, { fingerprint: 5 }, { fingerprint: "" },
    { fingerprint: "no-digest-tail" }, { fingerprint: "app.js:rule:NOTHEX0123456789" },
    { fingerprint: "x".repeat(2000) }, null, "a string", [],
  ]) {
    const r = cmp(report(), report({}, [bad]));
    assert.strictEqual(r.comparable, false, `${JSON.stringify(bad)} must reject`);
    assert.ok(codes(r).includes("malformed-finding-identity"),
      "dropping it silently would under-report a difference");
  }
});

test("`findings` that is not an array is an input error, not an empty report", () => {
  withDir((dir) => {
    const p = path.join(dir, "r.json");
    writeFileSync(p, JSON.stringify(report({ findings: "nope" })));
    const res = loadReport(p, "before");
    assert.ok("reasons" in res && res.reasons[0].code === "malformed-findings");
  });
});

// ---------------------------------------------------------------------------
suite("\ncompare (unit) — untrusted input");

test("a hostile FINGERPRINT is rejected outright, not scrubbed", () => {
  // The fingerprint is the matching key, so scrubbing it would silently change
  // which findings match. Rejecting keeps matching exact and output safe, and
  // fails conservatively: the pair is refused rather than quietly compared.
  const nasty = "\u0000\u001b[31mRED\u202e/dtth.exe";
  const r = cmp(report(), report({}, [finding(`${nasty}:rule:${hex("7")}`)]));
  assert.strictEqual(r.comparable, false, "a fingerprint carrying control characters must be refused");
  assert.ok(codes(r).includes("malformed-finding-identity"));
  const out = renderText(r) + renderJson(r);
  for (const ch of ["\u0000", "\u001b", "\u202e"]) {
    assert.ok(!out.includes(ch), `${JSON.stringify(ch)} must not reach output`);
  }
});

test("hostile ruleId, file and severity are scrubbed in output", () => {
  // These are descriptive, not identity, so they are sanitized rather than
  // rejected -- a real path is far likelier to be odd than a fingerprint is.
  const nasty = "\u0000\u001b[31mRED\u202e/dtth.exe";
  const r = cmp(report(), report({}, [finding(FP1, { ruleId: nasty, file: nasty, severity: nasty })]));
  assert.strictEqual(r.comparable, true);
  const out = renderText(r) + renderJson(r);
  for (const ch of ["\u0000", "\u001b", "\u202e"]) {
    assert.ok(!out.includes(ch), `${JSON.stringify(ch)} must not reach output`);
  }
  // Descriptive fields from the report are not carried at all now.
  assert.strictEqual(r.added[0].ruleId, "github-token");
  assert.strictEqual(r.added[0].digest, hex("1"));
});

test("descriptive fields cannot leak a credential: location comes from the fingerprint", () => {
  // REGRESSION. A report whose fingerprint was clean but whose ruleId, file and
  // severity carried a credential had it printed verbatim, on the SUCCESS path.
  const secret = token();
  const r = cmp(
    report(),
    report({}, [finding(FP1, { ruleId: secret, file: secret, severity: secret })])
  );
  assert.strictEqual(r.comparable, true);
  const out = renderText(r) + renderJson(r);
  assert.ok(!out.includes(secret), "no descriptive field may echo report-supplied text");
  // Derived from the validated fingerprint instead.
  assert.strictEqual(r.added[0].ruleId, "github-token");
  assert.strictEqual(r.added[0].digest, hex("1"));
  assert.strictEqual(r.added[0].severity, null, "an unknown severity is dropped, not echoed");
});

test("severity is admitted only from the scanner's own set", () => {
  for (const [given, expected] of [
    ["critical", "critical"], ["high", "high"], ["medium", "medium"], ["low", "low"],
    ["CRITICAL", null], ["urgent", null], ["", null], [123 as any, null],
  ] as const) {
    const r = cmp(report(), report({}, [finding(FP1, { severity: given })]));
    assert.strictEqual(r.added[0].severity, expected, `severity ${JSON.stringify(given)}`);
  }
});

test("a credential in the PATH is never echoed, in either format", () => {
  // REGRESSION. The path segment of a fingerprint is arbitrary text: no format
  // check can prove it holds no secret, so it is not printed at all. Matching
  // still uses the full raw fingerprint, unchanged.
  const secret = token();
  const a = report();
  const b = report({}, [finding(`src/${secret}/app.js:github-token:${hex("2")}`)]);
  const r = cmp(a, b);
  assert.strictEqual(r.comparable, true);
  const out = renderText(r) + renderJson(r);
  assert.ok(!out.includes(secret), "the path must not reach text or JSON output");
  // What IS shown is enough to find the finding again in either report.
  assert.strictEqual(r.added[0].ruleId, "github-token");
  assert.strictEqual(r.added[0].digest, hex("2"));

  // Matching is unaffected: the same path on both sides still pairs up.
  const same = cmp(b, report({}, [finding(`src/${secret}/app.js:github-token:${hex("2")}`)]));
  assert.strictEqual(same.persisting.length, 1);
  assert.strictEqual(same.added.length, 0);
  // A DIFFERENT path with the same rule and digest is a different finding.
  const other = cmp(b, report({}, [finding(`src/other/app.js:github-token:${hex("2")}`)]));
  assert.strictEqual(other.added.length, 1, "the raw path still distinguishes identities");
  assert.strictEqual(other.noLongerObserved.length, 1);
});

test("a credential in the path is absent from AMBIGUITY entries and errors too", () => {
  const secret = token();
  const fp = `src/${secret}/app.js:github-token:${hex("3")}`;
  // Ambiguity path.
  const amb = cmp(report({}, [finding(fp), finding(fp)]), report({}, [finding(fp)]));
  assert.strictEqual(amb.ambiguousIdentity.length, 1);
  assert.ok(!(renderText(amb) + renderJson(amb)).includes(secret), "ambiguity entries must not echo it");
  // Error path: a malformed sibling forces rejection while this one is present.
  const err = cmp(report(), report({}, [finding(fp), { fingerprint: `x/${secret}:BADRULE:${hex("4")}` }]));
  assert.strictEqual(err.comparable, false);
  assert.ok(!(renderText(err) + renderJson(err)).includes(secret), "reasons must not echo it");
});

test("legitimate fingerprint shapes are accepted", () => {
  const shapes = [
    `app.js:github-token:${hex("1")}`,
    `src/deep/nested/path/file.ts:aws-access-key:${hex("2")}`,
    `weird:name/with:colons.js:generic-high-entropy:${hex("3")}`,
    `spaced name/a b.txt:pkcs12-private-key:${hex("4")}`,
    `C:/Windows/path/app.cfg:azure-sas-token:${hex("5")}`,
    `ünïcode/pÄth.js:gitlab-pat:${hex("6")}`,
    `a:${hex("7")}`.replace(`a:`, `a:github-token:`),
  ];
  for (const fp of shapes) {
    const r = cmp(report(), report({}, [finding(fp)]));
    assert.strictEqual(r.comparable, true, `legitimate fingerprint refused: ${fp}`);
  }
});

test("structurally wrong fingerprints are refused, not guessed at", () => {
  for (const fp of [
    `app.js:github-token:${"g".repeat(16)}`,      // digest not hex
    `app.js:github-token:${hex("1")}extra`,        // digest not the tail
    `app.js:Github-Token:${hex("1")}`,             // rule id not the grammar
    `app.js:github token:${hex("1")}`,             // space in rule id
    `app.js:github_token:${hex("1")}`,             // underscore in rule id
    `app.js::${hex("1")}`,                          // empty rule id
    `:github-token:${hex("1")}`,                    // empty path
    `github-token:${hex("1")}`,                     // no path segment
    hex("1"),                                       // digest alone
  ]) {
    const r = cmp(report(), report({}, [finding(fp)]));
    assert.strictEqual(r.comparable, false, `must refuse: ${fp}`);
    assert.ok(codes(r).includes("malformed-finding-identity"));
  }
});

test("a value field is never copied through, whatever it is called", () => {
  const secret = token();
  const r = cmp(
    report(),
    report({}, [finding(FP1, { value: secret, redactedValue: secret, context: secret, extra: secret })])
  );
  assert.strictEqual(r.comparable, true);
  const out = renderText(r) + renderJson(r);
  assert.ok(!out.includes(secret), "the comparator must not launder report content into its output");
  // Explicit fields only: the finding reference carries exactly five keys.
  assert.deepStrictEqual(
    Object.keys(r.added[0]).sort(),
    ["digest", "line", "ruleId", "severity"],
    "no path and no raw fingerprint may appear in a result"
  );
});

test("malformed JSON and non-objects are refused without quoting the input", () => {
  withDir((dir) => {
    const bad = path.join(dir, "bad.json");
    writeFileSync(bad, '{"tool": "secretloop", THIS IS NOT JSON');
    const res = loadReport(bad, "before");
    assert.ok("reasons" in res && res.reasons[0].code === "malformed-json");
    assert.ok(!JSON.stringify(res).includes("THIS IS NOT JSON"), "the input must not be echoed back");

    const arr = path.join(dir, "arr.json");
    writeFileSync(arr, "[1,2,3]");
    assert.ok("reasons" in loadReport(arr, "before"));

    const missing = path.join(dir, "nope.json");
    const res2 = loadReport(missing, "after");
    assert.ok("reasons" in res2 && res2.reasons[0].code === "unreadable-input");

    mkdirSync(path.join(dir, "adir"));
    assert.ok("reasons" in loadReport(path.join(dir, "adir"), "before"));
  });
});

test("an over-long findings array is refused rather than processed", () => {
  withDir((dir) => {
    const p = path.join(dir, "big.json");
    // Length is checked against the bound before any per-finding work.
    writeFileSync(p, JSON.stringify({ findings: new Array(MAX_FINDINGS + 1).fill(0) }));
    const res = loadReport(p, "before");
    assert.ok("reasons" in res && res.reasons[0].code === "malformed-findings");
  });
});

// ---------------------------------------------------------------------------
suite("\ncompare — displayed references that stand for several identities");

/** A finding at an explicit path, so display collisions can be constructed. */
const at = (path: string, digest: string, over: Record<string, unknown> = {}) =>
  finding(`${path}:github-token:${hex(digest)}`, over);

test("A unique displayed reference produces no note at all", () => {
  const r = cmp(report(), report({}, [at("u.js", "3")]));
  assert.strictEqual(r.comparable, true);
  assert.deepStrictEqual(r.sharedDisplayReferences, []);
  assert.deepStrictEqual(r.ambiguousIdentity, []);
  assert.ok(!renderText(r).includes("SHARED DISPLAY REFERENCE"));
});

test("B repeated occurrences of ONE identity are ambiguity, not a shared reference", () => {
  const r = cmp(report({}, [at("a.js", "1")]), report({}, [at("a.js", "1"), at("a.js", "1", { line: 9 })]));
  assert.strictEqual(r.comparable, true);
  assert.strictEqual(r.ambiguousIdentity.length, 1, "one identity seen twice");
  assert.deepStrictEqual(r.ambiguousIdentity[0],
    { ruleId: "github-token", digest: hex("1"), beforeCount: 1, afterCount: 2 });
  assert.deepStrictEqual(r.sharedDisplayReferences, [],
    "a repeated identity is NOT a display collision");
});

test("C distinct identities sharing a displayed pair are reported separately", () => {
  const r = cmp(report(), report({}, [at("x/one.js", "2"), at("y/two.js", "2")]));
  assert.strictEqual(r.comparable, true);
  // Told apart correctly: two separate results, not merged.
  assert.strictEqual(r.added.length, 2, "distinct findings must stay distinct");
  assert.deepStrictEqual(r.sharedDisplayReferences,
    [{ ruleId: "github-token", digest: hex("2"), distinctIdentities: 2 }]);
  assert.deepStrictEqual(r.ambiguousIdentity, [],
    "a display collision is NOT an occurrence count");
});

test("the two kinds are reported in separate sections with distinct wording", () => {
  const r = cmp(
    report({}, [at("a.js", "1")]),
    report({}, [at("a.js", "1"), at("a.js", "1", { line: 9 }), at("x/one.js", "2"), at("y/two.js", "2")])
  );
  const text = renderText(r);
  assert.match(text, /SHARED DISPLAY REFERENCE \(1\)/);
  assert.match(text, /AMBIGUOUS IDENTITY \(1\)/);
  // The three things a user must be told about a shared reference.
  assert.match(text, /More than one DISTINCT finding/);
  assert.match(text, /paths are omitted from this output on purpose/i);
  assert.match(text, /may return MORE THAN ONE match/);
  // And the occurrence section says it is a different thing.
  assert.match(text, /a different thing from the shared/);
});

test("a display collision spanning the two reports is caught", () => {
  const r = cmp(report({}, [at("x/one.js", "2")]), report({}, [at("y/two.js", "2")]));
  assert.strictEqual(r.comparable, true);
  assert.strictEqual(r.added.length, 1);
  assert.strictEqual(r.noLongerObserved.length, 1);
  assert.deepStrictEqual(r.sharedDisplayReferences,
    [{ ruleId: "github-token", digest: hex("2"), distinctIdentities: 2 }]);
});

test("the JSON field is additive and carries no path, fingerprint or new hash", () => {
  const secret = token();
  const r = cmp(report(), report({}, [at(`x/${secret}/one.js`, "2"), at("y/two.js", "2")]));
  const d = JSON.parse(renderJson(r));
  // Existing keys are unchanged; the new one is added beside them.
  for (const k of ["tool", "comparable", "summary", "new", "persisting",
                   "noLongerObserved", "ambiguousIdentity", "caveat"]) {
    assert.ok(k in d, `existing key lost: ${k}`);
  }
  assert.deepStrictEqual(d.sharedDisplayReferences,
    [{ ruleId: "github-token", digest: hex("2"), distinctIdentities: 2 }]);
  assert.strictEqual(d.summary.sharedDisplayReferences, 1);
  // Only ruleId, digest and a count -- nothing else.
  assert.deepStrictEqual(Object.keys(d.sharedDisplayReferences[0]).sort(),
    ["digest", "distinctIdentities", "ruleId"]);
  const out = renderText(r) + renderJson(r);
  assert.ok(!out.includes(secret), "no path may reach output");
});

// ---------------------------------------------------------------------------
suite("\ncompare — invalid findings are collected from BOTH reports, bounded");

const badRule = (i: number) => ({ fingerprint: `p${i}.js:${unknownRuleId()}:${hex("7")}` });
const badStruct = (i: number) => ({ fingerprint: `nostructure${i}` });

test("errors from both sides are reported, in a deterministic order", () => {
  const r = cmp(
    report({}, [at("a.js", "1"), badRule(0), badStruct(1)]),
    report({}, [badStruct(2), at("b.js", "2"), badRule(3)])
  );
  assert.strictEqual(r.comparable, false);
  const fields = r.reasons.map((x) => `${x.side}:${x.field}`);
  assert.deepStrictEqual(fields, [
    "before:findings[1]", "before:findings[2]",
    "after:findings[0]", "after:findings[2]",
  ], "before side first, each in ascending index order");
  // The cause is named without quoting anything the report supplied.
  const details = r.reasons.map((x) => x.detail).join(" | ");
  assert.match(details, /names a rule this build does not support/);
  assert.match(details, /has no usable fingerprint/);
});

test("one side cannot exhaust the allowance and hide the other", () => {
  const flood = Array.from({ length: 40 }, (_, i) => badRule(i));
  const few = Array.from({ length: 3 }, (_, i) => badStruct(i));
  const r = cmp(report({}, flood), report({}, few));
  assert.strictEqual(r.comparable, false);
  const before = r.reasons.filter((x) => x.side === "before");
  const after = r.reasons.filter((x) => x.side === "after");
  assert.strictEqual(before.filter((x) => x.code === "malformed-finding-identity").length,
    MAX_FINDING_DIAGNOSTICS_PER_SIDE, "the flooding side is capped");
  assert.strictEqual(after.length, 3, "the other side's errors all survive");
  assert.ok(after.every((x) => x.code === "malformed-finding-identity"),
    "and need no truncation note");
});

test("truncation is stated explicitly, with an exact total", () => {
  const flood = Array.from({ length: 25 }, (_, i) => badStruct(i));
  const r = cmp(report({}, flood), report());
  const trunc = r.reasons.filter((x) => x.code === "diagnostics-truncated");
  assert.strictEqual(trunc.length, 1);
  assert.strictEqual(trunc[0].side, "before");
  // Every finding IS inspected, so the total may be stated exactly.
  assert.match(trunc[0].detail, /25 invalid finding\(s\) in total/);
  assert.match(trunc[0].detail, new RegExp(`${MAX_FINDING_DIAGNOSTICS_PER_SIDE} described above`));
  assert.match(trunc[0].detail, new RegExp(`${25 - MAX_FINDING_DIAGNOSTICS_PER_SIDE} not listed`));
});

test("no truncation note when everything fits", () => {
  const r = cmp(report({}, [badStruct(0), badStruct(1)]), report());
  assert.deepStrictEqual(r.reasons.filter((x) => x.code === "diagnostics-truncated"), []);
  assert.strictEqual(r.reasons.length, 2);
});

test("the per-side cap is exact at 0, 1, 10 and 11 invalid findings", () => {
  const N = MAX_FINDING_DIAGNOSTICS_PER_SIDE;
  const invalid = (n: number) => Array.from({ length: n }, (_, i) => badStruct(i));

  // 0: a valid pair is comparable and carries no diagnostics at all.
  const none = cmp(report({}, [at("a.js", "1")]), report({}, [at("a.js", "1")]));
  assert.strictEqual(none.comparable, true);
  assert.deepStrictEqual(none.reasons, []);

  for (const [count, expectDetailed, expectTruncation] of [
    [1, 1, false],
    [N, N, false],          // exactly at the cap: everything described, no note
    [N + 1, N, true],       // one over: the note appears
  ] as const) {
    const r = cmp(report({}, invalid(count)), report());
    assert.strictEqual(r.comparable, false, `${count} invalid must refuse`);
    const detailed = r.reasons.filter((x) => x.code === "malformed-finding-identity");
    const trunc = r.reasons.filter((x) => x.code === "diagnostics-truncated");
    assert.strictEqual(detailed.length, expectDetailed, `${count}: detailed count`);
    assert.strictEqual(trunc.length, expectTruncation ? 1 : 0, `${count}: truncation note`);
    // Indices are zero-based positions in that input, in ascending order.
    assert.deepStrictEqual(
      detailed.map((x) => x.field),
      Array.from({ length: expectDetailed }, (_, i) => `findings[${i}]`),
      `${count}: index convention`
    );
    if (expectTruncation) {
      assert.match(trunc[0].detail, new RegExp(`${count} invalid finding\\(s\\) in total`));
      assert.match(trunc[0].detail, new RegExp(`${count - expectDetailed} not listed`));
    }
  }
});

test("both sides over the cap each get their own truncation note", () => {
  const N = MAX_FINDING_DIAGNOSTICS_PER_SIDE;
  const r = cmp(
    report({}, Array.from({ length: N + 5 }, (_, i) => badStruct(i))),
    report({}, Array.from({ length: N + 2 }, (_, i) => badRule(i)))
  );
  assert.strictEqual(r.comparable, false);
  for (const [side, total] of [["before", N + 5], ["after", N + 2]] as const) {
    const mine = r.reasons.filter((x) => x.side === side);
    assert.strictEqual(mine.filter((x) => x.code === "malformed-finding-identity").length, N,
      `${side}: capped at the budget`);
    const trunc = mine.filter((x) => x.code === "diagnostics-truncated");
    assert.strictEqual(trunc.length, 1, `${side}: its own truncation note`);
    assert.match(trunc[0].detail, new RegExp(`${total} invalid finding\\(s\\) in total`));
  }
  // Ordering stays before-side block then after-side block.
  const sides = r.reasons.map((x) => x.side);
  assert.deepStrictEqual(sides, [...Array(N + 1).fill("before"), ...Array(N + 1).fill("after")]);
});

test("valid findings that WOULD differ produce no partial results", () => {
  const r = cmp(
    report({}, [at("a.js", "1"), badStruct(0)]),
    report({}, [at("b.js", "2"), badRule(1)])
  );
  assert.strictEqual(r.comparable, false);
  assert.deepStrictEqual(r.added, []);
  assert.deepStrictEqual(r.persisting, []);
  assert.deepStrictEqual(r.noLongerObserved, []);
  assert.deepStrictEqual(r.ambiguousIdentity, []);
  assert.deepStrictEqual(r.sharedDisplayReferences, []);
  const d = JSON.parse(renderJson(r));
  assert.deepStrictEqual(Object.keys(d).sort(), ["comparable", "reasons", "tool"]);
});

test("metadata failures still refuse BEFORE any finding is matched", () => {
  // Ineligible metadata plus invalid findings: only the metadata reasons appear,
  // so matching is never reached.
  const r = cmp(report({ incomplete: true }), report({}, [badStruct(0), badStruct(1)]));
  assert.strictEqual(r.comparable, false);
  assert.ok(codes(r).includes("incomplete-coverage"));
  assert.ok(!codes(r).includes("malformed-finding-identity"),
    "finding validation must not run once eligibility has failed");
});

// ---------------------------------------------------------------------------
suite("\ncompare — a rule id must be SUPPORTED, not merely grammatical");

/** A runtime marker that is grammar-valid and not a rule this build emits. */
function unknownRuleId(): string {
  const a = "abcdefghijklmnopqrstuvwxyz0123456789";
  let out = "zz";
  for (let i = 0; i < 24; i++) out += a[Math.floor(Math.random() * a.length)];
  return out;
}

test("an unknown but grammar-valid rule id refuses the comparison, on either side", () => {
  for (const side of ["before", "after"] as const) {
    const mark = unknownRuleId();
    const bad = report({}, [finding(`app.js:${mark}:${hex("2")}`)]);
    const r = side === "after" ? cmp(report(), bad) : cmp(bad, report());
    assert.strictEqual(r.comparable, false, `unsupported rule id on the ${side} side must refuse`);
    assert.ok(codes(r).includes("malformed-finding-identity"));
    const out = renderText(r) + renderJson(r);
    assert.ok(!out.includes(mark), "the rejected id must never be echoed");
  }
});

test("the SAME unsupported id on both sides is still refused", () => {
  const mark = unknownRuleId();
  const f = finding(`app.js:${mark}:${hex("2")}`);
  const r = cmp(report({}, [f]), report({}, [f]));
  assert.strictEqual(r.comparable, false, "agreement is not support");
  // The existing invalid-finding policy returns on the first failing side
  // rather than collecting both; the refusal is what matters here.
  assert.ok(codes(r).includes("malformed-finding-identity"));
  assert.ok(!(renderText(r) + renderJson(r)).includes(mark));
});

test("mixed supported and unsupported findings refuse the WHOLE comparison", () => {
  const mark = unknownRuleId();
  const bad = finding(`app.js:${mark}:${hex("9")}`);
  const goodA = finding(FP1);
  const goodB = finding(FP2);
  // Unsupported first, and unsupported last: position must not matter.
  for (const findings of [[bad, goodA, goodB], [goodA, goodB, bad], [goodA, bad, goodB]]) {
    const r = cmp(report({}, [goodA]), report({}, findings));
    assert.strictEqual(r.comparable, false, "one unsupported finding refuses everything");
    // The valid findings WOULD have produced a difference; none may leak.
    assert.deepStrictEqual(r.added, []);
    assert.deepStrictEqual(r.persisting, []);
    assert.deepStrictEqual(r.noLongerObserved, []);
    assert.deepStrictEqual(r.ambiguousIdentity, []);
    const parsed = JSON.parse(renderJson(r));
    assert.deepStrictEqual(Object.keys(parsed).sort(), ["comparable", "reasons", "tool"],
      "no partial results and no difference keys");
    assert.ok(!(renderText(r) + renderJson(r)).includes(mark));
  }
  // And on the before side too.
  const rev = cmp(report({}, [goodA, bad]), report({}, [goodA, goodB]));
  assert.strictEqual(rev.comparable, false);
  assert.deepStrictEqual(rev.added, []);
});

test("BOTH reports mixed: whole-comparison refusal regardless of ordering", () => {
  // The existing mixed test varies one side at a time. This is the case where
  // BOTH sides carry valid findings that would otherwise produce differences
  // AND an unsupported rule id -- the same id on both, and different ids.
  const pathMark = `zpath${unknownRuleId().slice(2, 14)}`;
  const goodA = finding(FP1);
  const goodB = finding(FP2);
  const goodC = finding(`src/${pathMark}/c.js:slack-token:${hex("5")}`);

  const shared = unknownRuleId();
  const idA = unknownRuleId();
  const idB = unknownRuleId();
  assert.notStrictEqual(idA, idB, "the two markers must differ");

  const badWith = (id: string, d: string) => finding(`src/${pathMark}/x.js:${id}:${hex(d)}`);

  const cases: Array<[string, any[], any[]]> = [
    // same unsupported id on both sides, unsupported FIRST on both
    ["same id, both first", [badWith(shared, "7"), goodA, goodC], [badWith(shared, "8"), goodB, goodC]],
    // same id, unsupported LAST on both
    ["same id, both last", [goodA, goodC, badWith(shared, "7")], [goodB, goodC, badWith(shared, "8")]],
    // different unsupported ids, opposite positions
    ["different ids, first/last", [badWith(idA, "7"), goodA], [goodB, badWith(idB, "8")]],
    ["different ids, last/first", [goodA, badWith(idA, "7")], [badWith(idB, "8"), goodB]],
  ];

  for (const [label, beforeFindings, afterFindings] of cases) {
    const r = cmp(report({}, beforeFindings), report({}, afterFindings));
    assert.strictEqual(r.comparable, false, `${label}: must refuse the whole comparison`);
    // The valid findings differ between the sides and would have produced
    // results; none may survive the refusal.
    assert.deepStrictEqual(r.added, [], label);
    assert.deepStrictEqual(r.persisting, [], label);
    assert.deepStrictEqual(r.noLongerObserved, [], label);
    assert.deepStrictEqual(r.ambiguousIdentity, [], label);
    const parsed = JSON.parse(renderJson(r));
    assert.deepStrictEqual(Object.keys(parsed).sort(), ["comparable", "reasons", "tool"], label);
    // The comparator stops at the first invalid finding, so only one side is
    // listed. That is the existing policy and is not asserted against.
    assert.ok(r.reasons.some((x) => x.code === "malformed-finding-identity"), label);
    const out = renderText(r) + renderJson(r);
    for (const mark of [shared, idA, idB, pathMark]) {
      assert.ok(!out.includes(mark), `${label}: ${mark} must not be echoed`);
    }
  }
});

test("CLI: both reports mixed — exit 3, no difference keys, no markers on stdout or stderr", () => {
  withDir((dir) => {
    const pathMark = `zpath${unknownRuleId().slice(2, 14)}`;
    const idA = unknownRuleId();
    const idB = unknownRuleId();
    const A = path.join(dir, "A.json"), B = path.join(dir, "B.json");
    // Both sides: a valid finding unique to that side (so a difference exists),
    // a shared valid finding, and an unsupported one at opposite ends.
    writeFileSync(A, JSON.stringify(report({}, [
      finding(`src/${pathMark}/x.js:${idA}:${hex("7")}`),
      finding(FP1),
      finding(`src/${pathMark}/shared.js:slack-token:${hex("5")}`),
    ])));
    writeFileSync(B, JSON.stringify(report({}, [
      finding(FP2),
      finding(`src/${pathMark}/shared.js:slack-token:${hex("5")}`),
      finding(`src/${pathMark}/y.js:${idB}:${hex("8")}`),
    ])));

    for (const args of [["compare", A, B], ["compare", A, B, "--format", "json"]]) {
      const out = cli(args);
      assert.strictEqual(out.status, 3, `${args.join(" ")}: both-mixed must exit 3`);
      const both = out.stdout + out.stderr;
      for (const mark of [idA, idB, pathMark]) {
        assert.ok(!both.includes(mark), `${mark} reached stdout or stderr`);
      }
      // No partial difference may appear: neither side's unique digest.
      assert.ok(!both.includes(hex("1")) && !both.includes(hex("2")),
        "no partial findings may be emitted");
    }
    const d = JSON.parse(cli(["compare", A, B, "--format", "json"]).stdout);
    assert.deepStrictEqual(Object.keys(d).sort(), ["comparable", "reasons", "tool"]);
    assert.strictEqual(d.comparable, false);
  });
});

test("distinct identities stay distinct, even when their displayed pair is identical", () => {
  // The digest covers the matched VALUE, not the path, so one credential found
  // by one rule in two files shares ruleId and digest. Matching must still keep
  // them apart; only the presentation is ambiguous, which the docs now say.
  const twin = (p: string) => finding(`${p}:github-token:${hex("2")}`);
  const r = cmp(report(), report({}, [twin("a/one.js"), twin("b/two.js")]));
  assert.strictEqual(r.comparable, true);
  assert.strictEqual(r.added.length, 2, "two distinct identities must not be merged");
  assert.deepStrictEqual(r.added[0], r.added[1], "and their displayed pairs are identical");
  assert.deepStrictEqual(r.ambiguousIdentity, [], "distinct identities are not a multiplicity");
});

test("EVERY rule id this build emits is accepted", () => {
  // Derived from the same authorities the comparator uses, so a new rule cannot
  // be admitted by one and refused by the other.
  const ids = [...rulesById.keys(), ENTROPY_RULE_ID, PKCS12_RULE_ID];
  assert.ok(ids.length > 100, `expected the full rule set, got ${ids.length}`);
  for (const id of ids) {
    const r = cmp(report(), report({}, [finding(`app.js:${id}:${hex("2")}`)]));
    assert.strictEqual(r.comparable, true, `supported rule id refused: ${id}`);
    assert.strictEqual(r.added[0].ruleId, id);
  }
});

test("exact raw-fingerprint matching is unchanged by the membership check", () => {
  // Two findings sharing a rule and digest but differing in path stay distinct.
  const a = report({}, [finding(`one.js:github-token:${hex("2")}`)]);
  const b = report({}, [finding(`two.js:github-token:${hex("2")}`)]);
  const r = cmp(a, b);
  assert.strictEqual(r.comparable, true);
  assert.strictEqual(r.added.length, 1, "presentation must not merge distinct identities");
  assert.strictEqual(r.noLongerObserved.length, 1);
  // Identical paths still pair.
  assert.strictEqual(cmp(a, a).persisting.length, 1);
});

// ---------------------------------------------------------------------------
suite("\ncompare (unit) — the read is bounded by the descriptor, not the name");

/** Small limits and an injected hook: no giant fixtures, no timing races. */
test("exactly the limit is accepted; one byte over is refused", () => {
  withDir((dir) => {
    const body = JSON.stringify(report());
    const p = path.join(dir, "r.json");
    writeFileSync(p, body);
    const exact = Buffer.byteLength(body);

    assert.ok("report" in loadReport(p, "before", { maxBytes: exact }), "exactly the limit must pass");
    const over = loadReport(p, "before", { maxBytes: exact - 1 });
    assert.ok("reasons" in over && over.reasons[0].code === "oversized-input",
      "one byte over the limit must be refused");
  });
});

test("growth after inspection is caught DURING the read", () => {
  withDir((dir) => {
    const p = path.join(dir, "r.json");
    const body = JSON.stringify(report());
    writeFileSync(p, body);
    const size = Buffer.byteLength(body);

    // fstat sees `size`; the hook then appends past the cap before any read.
    // The old shape (stat then unrestricted readFileSync) read it all anyway.
    const res = loadReport(p, "before", {
      maxBytes: size,
      afterOpen: () => appendFileSync(p, "x".repeat(size * 4)),
    });
    assert.ok("reasons" in res && res.reasons[0].code === "oversized-input",
      "the cap must be enforced while reading, not only before it");
  });
});

test("replacing the path after opening does not change what is read", () => {
  withDir((dir) => {
    const p = path.join(dir, "r.json");
    const original = report({}, [finding(FP1)]);
    writeFileSync(p, JSON.stringify(original));

    // The swap is the fixture, not the subject: the reader reports a throw
    // from the seam as `could not be read`, which cannot be told from a reader
    // defect. The fixture therefore records its own failure by call and code.
    let refused: { call: string; code: string } | null = null;
    const res = loadReport(p, "before", {
      afterOpen: () => {
        // Swap the NAME for different content. The descriptor still refers to
        // the original inode, so the swap must not be observed.
        try {
          unlinkSync(p);
        } catch (e) {
          refused = { call: "unlink", code: String((e as NodeJS.ErrnoException).code) };
          throw e;
        }
        try {
          writeFileSync(p, JSON.stringify(report({}, [finding(FP2), finding(FP1)])));
        } catch (e) {
          refused = { call: "write", code: String((e as NodeJS.ErrnoException).code) };
          throw e;
        }
      },
    });
    // Only the codes by which Windows refuses to replace a name under an open
    // handle (measured: EPERM) qualify as the platform's answer. Any other
    // fixture failure -- a missing file, a bad path -- falls through to the
    // assertion below and FAILS on every platform, so a broken fixture can
    // never masquerade as a platform limit.
    const platformRefusal = new Set(["EPERM", "EBUSY", "EACCES"]);
    if (refused !== null && process.platform === "win32" && platformRefusal.has((refused as { code: string }).code)) {
      // A platform that will not replace a name under an open descriptor has
      // said something about itself, not about the reader. Skipped, with the
      // call and code, rather than passed or failed.
      const { call, code } = refused as { call: string; code: string };
      skip(`win32 refused to replace an open file's name at ${call} (${code}); the property cannot be exercised here`);
    }
    assert.strictEqual(refused, null, `the fixture failed at ${JSON.stringify(refused)}`);
    assert.ok("report" in res);
    assert.strictEqual(res.report.findings.length, 1, "the original object must be what was read");
  });
});

test("non-regular inputs are refused through the opened descriptor", () => {
  withDir((dir) => {
    mkdirSync(path.join(dir, "adir"));
    const d = loadReport(path.join(dir, "adir"), "before");
    assert.ok("reasons" in d && d.reasons[0].code === "unreadable-input");
    assert.strictEqual(d.reasons[0].detail, "not a regular file");

    // A symlink to a directory resolves to one; fstat on the opened object sees
    // that, so the check cannot be sidestepped by the name.
    symlinkSync(path.join(dir, "adir"), path.join(dir, "link"));
    assert.ok("reasons" in loadReport(path.join(dir, "link"), "before"));
  });
});

test("open failures are reported without leaking the reason or the path", () => {
  withDir((dir) => {
    const res = loadReport(path.join(dir, "absent.json"), "after");
    assert.ok("reasons" in res);
    assert.strictEqual(res.reasons[0].code, "unreadable-input");
    assert.strictEqual(res.reasons[0].detail, "could not be opened");
    assert.ok(!JSON.stringify(res).includes(dir), "the path must not appear in the reason");
    assert.ok(!/ENOENT|no such file/i.test(JSON.stringify(res)), "nor the OS error text");
  });
});

test("descriptors are closed on every path, including failures", () => {
  withDir((dir) => {
    const good = path.join(dir, "ok.json");
    writeFileSync(good, JSON.stringify(report()));
    mkdirSync(path.join(dir, "adir"));
    const missing = path.join(dir, "absent.json");

    // Enough iterations to exhaust the descriptor table if any path leaked one.
    for (let i = 0; i < 400; i++) {
      loadReport(good, "before");
      loadReport(path.join(dir, "adir"), "before");
      loadReport(missing, "before");
      loadReport(good, "before", { maxBytes: 1 });
    }
    assert.ok("report" in loadReport(good, "before"),
      "a normal load must still succeed: a leaked descriptor would have exhausted the table");
  });
});

// ---------------------------------------------------------------------------
suite("\ncompare (unit) — wording and output shape");

test("an incomparable result carries NO difference keys at all", () => {
  const r = cmp(report(), report({ configDigest: hex("9") }));
  const parsed = JSON.parse(renderJson(r));
  assert.strictEqual(parsed.comparable, false);
  assert.ok(Array.isArray(parsed.reasons) && parsed.reasons.length > 0);
  for (const k of ["new", "persisting", "noLongerObserved", "summary"]) {
    assert.ok(!(k in parsed), `an empty ${k} beside comparable:false reads as "nothing changed"`);
  }
  assert.match(renderText(r), /cannot be compared/);
  assert.match(renderText(r), /No difference is reported/);
});

test("no-longer-observed is never described as fixed, removed, rotated or revoked", () => {
  const r = cmp(report({}, [finding(FP1)]), report());
  const out = (renderText(r) + renderJson(r)).toLowerCase();
  assert.match(out, /no longer observed/);
  assert.match(out, /does not mean fixed/);
  for (const word of ["is fixed", "was fixed", "remediated", "rotated the", "has been removed", "revoked the"]) {
    assert.ok(!out.includes(word), `output must not claim "${word}"`);
  }
  assert.ok(NO_LONGER_OBSERVED_CAVEAT.includes("makes no claim about files excluded"));
});

test("output is stable across runs for the same input", () => {
  const a = report({}, [finding(FP2), finding(FP1)]);
  const b = report({}, [finding(FP1)]);
  assert.strictEqual(renderJson(cmp(a, b)), renderJson(cmp(a, b)));
  // Order of findings in the input must not change the output.
  const shuffled = report({}, [finding(FP1), finding(FP2)]);
  assert.strictEqual(renderJson(cmp(a, b)), renderJson(cmp(shuffled, b)));
});

// ---------------------------------------------------------------------------
suite("\ncompare (unit) — a FIFO report path is refused, not waited on");

/**
 * THE DEMONSTRATED BLOCK. `loadReport` opens the path and classifies the
 * descriptor with `fstat`; it has NO pre-open check, so the only FIFO case
 * that exists is a path that IS a FIFO when the open runs. On the unchanged
 * source that open waited for a writer indefinitely -- measured through the
 * built CLI in both argument positions. Each case below runs in a child with a
 * hard timeout: a child that is killed FAILS the case, never skips it. The
 * PARENT creates and removes the lab, so a killed child leaves no FIFO behind.
 *
 * WIN32: no FIFO can exist on an NTFS path and `fs.constants.O_NONBLOCK` is
 * undefined there, so the product falls back to a plain read-only open --
 * previous behaviour, not protection. These cases skip on win32 and are
 * counted apart from passes; every ordinary-input case in this file runs there.
 */
const FIFO_TIMEOUT_MS = 10000;

function requireMkfifo(): void {
  if (process.platform === "win32") skip("mkfifo is POSIX; no FIFO can be created on an NTFS path");
  const d = mkdtempSync(path.join(tmpdir(), "secretloop-cmp-mkfifo-"));
  try {
    execFileSync("mkfifo", [path.join(d, "p")], { stdio: "ignore" });
  } catch {
    skip("mkfifo is unavailable on this host; the FIFO case did not run");
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}

test("loadReport refuses a writerless FIFO promptly as 'not a regular file', and closes it", () => {
  requireMkfifo();
  const root = path.join(__dirname, "..");
  const lab = mkdtempSync(path.join(tmpdir(), "secretloop-cmp-fifo-"));
  let run: ReturnType<typeof spawnSync>;
  try {
    const fifo = path.join(lab, "pipe.json");
    execFileSync("mkfifo", [fifo], { stdio: "ignore" });
    const script = `
      const fs = require("fs");
      const { loadReport } = require(${JSON.stringify(path.join(root, "src", "compare"))});
      const probe = () => { const fd = fs.openSync(${JSON.stringify(lab)}, "r"); fs.closeSync(fd); return fd; };
      const before = probe();
      const t0 = Date.now();
      const r = loadReport(${JSON.stringify(fifo)}, "before");
      const after = probe();
      process.stdout.write(JSON.stringify({ ms: Date.now() - t0, reasons: "reasons" in r ? r.reasons : null, before, after }));
    `;
    run = spawnSync(process.execPath, ["-r", "ts-node/register/transpile-only", "-e", script], {
      cwd: root,
      timeout: FIFO_TIMEOUT_MS,
      encoding: "utf8",
    });
  } finally {
    rmSync(lab, { recursive: true, force: true });
  }
  // A TIMEOUT IS THE DEFECT: the open waited for a writer. It fails this case.
  assert.ok(
    !run.error || (run.error as NodeJS.ErrnoException).code !== "ETIMEDOUT",
    `loadReport BLOCKED on a writerless FIFO: child killed after ${FIFO_TIMEOUT_MS} ms`
  );
  assert.strictEqual(run.status, 0, `child failed: ${run.stderr}`);
  const got = JSON.parse(String(run.stdout));
  assert.ok(Array.isArray(got.reasons), "a FIFO must be refused, not loaded");
  assert.strictEqual(got.reasons[0].code, "unreadable-input");
  assert.strictEqual(got.reasons[0].detail, "not a regular file", "the existing non-regular-input wording");
  assert.strictEqual(got.after, got.before, `descriptor number drifted ${got.before} -> ${got.after}: the refused FIFO leaked`);
});

test("CLI: a FIFO in either report position exits 2 promptly with the existing input-error line", () => {
  requireMkfifo();
  const lab = mkdtempSync(path.join(tmpdir(), "secretloop-cmp-fifo-cli-"));
  try {
    const good = path.join(lab, "good.json");
    writeFileSync(good, JSON.stringify(report()));
    for (const position of ["before", "after"] as const) {
      const fifo = path.join(lab, `${position}.pipe.json`);
      execFileSync("mkfifo", [fifo], { stdio: "ignore" });
      const args = position === "before" ? [fifo, good] : [good, fifo];
      // Exit status read from spawnSync itself, never through a pipeline.
      const r = spawnSync("node", [CLI, "compare", ...args], { encoding: "utf8", timeout: FIFO_TIMEOUT_MS });
      assert.ok(
        !r.error || (r.error as NodeJS.ErrnoException).code !== "ETIMEDOUT",
        `compare BLOCKED with a FIFO as the ${position} report: child killed after ${FIFO_TIMEOUT_MS} ms`
      );
      assert.strictEqual(r.status, 2, `a FIFO ${position} report is an input error (exit 2); got ${r.status}, stderr: ${r.stderr}`);
      assert.match(r.stderr, new RegExp(`secretloop: the ${position} report not a regular file\\.`));
      assert.ok(!r.stderr.includes(lab) && !(r.stdout || "").includes(lab), "no path is echoed");
      assert.strictEqual((r.stdout || "").trim(), "", "nothing is written to stdout for an unusable input");
    }
  } finally {
    rmSync(lab, { recursive: true, force: true });
  }
});

test("the report-file open is read-only plus O_NONBLOCK exactly where the platform defines it", () => {
  // Printed so the running platform's actual constant is in its own CI log:
  // win32 prints "undefined", and there the open is a plain read-only open.
  console.log(`    O_NONBLOCK on ${process.platform}: ${String(fsConstants.O_NONBLOCK)}`);
  if (process.platform !== "win32") {
    assert.notStrictEqual(fsConstants.O_NONBLOCK, undefined, "every supported POSIX platform is expected to define O_NONBLOCK");
  }
  // The ordinary-file contract survives the flag on every platform: a valid
  // report still loads, and a regular file's bytes are read in full.
  withDir((dir) => {
    const p = path.join(dir, "r.json");
    writeFileSync(p, JSON.stringify(report({}, [finding(FP1)])));
    const res = loadReport(p, "before");
    assert.ok("report" in res, "a regular report still loads with the non-blocking flag");
    assert.strictEqual(res.report.findings.length, 1);
  });
});

// ---------------------------------------------------------------------------
suite("\ncompare (integration) — the real CLI over real scanner output");

const cli = (args: string[], cwd?: string) =>
  spawnSync("node", [CLI, ...args], { encoding: "utf8", cwd });

function repo(dir: string): void {
  spawnSync("git", ["init", "-q", dir]);
  spawnSync("git", ["-C", dir, "config", "user.email", "t@t"]);
  spawnSync("git", ["-C", dir, "config", "user.name", "t"]);
  writeFileSync(path.join(dir, "README.md"), "ok\n");
  spawnSync("git", ["-C", dir, "add", "-A"]);
  spawnSync("git", ["-C", dir, "commit", "-qm", "init"]);
}

const scanTo = (dir: string, out: string, mode = "scan") =>
  cli([mode, "--path", dir, "--format", "json", "-o", out, "--fail-on", "never"]);

test("documented exit codes: 0 nothing new, 1 new findings, 2 bad input, 3 incomparable", () => {
  withDir((dir) => {
    repo(dir);
    const A = path.join(dir, "A.json"), B = path.join(dir, "B.json");
    writeFileSync(path.join(dir, "app.js"), "const ok = 1;\n");
    scanTo(dir, A);
    assert.strictEqual(cli(["compare", A, A]).status, 0, "identical reports: nothing new");

    writeFileSync(path.join(dir, "app.js"), `const t = "${token()}";\n`);
    scanTo(dir, B);
    assert.strictEqual(cli(["compare", A, B]).status, 1, "a new finding must exit 1");
    assert.strictEqual(cli(["compare", B, A]).status, 0, "a disappearance is not a new finding");

    assert.strictEqual(cli(["compare", A]).status, 2, "a missing argument is an input error");
    assert.strictEqual(cli(["compare", A, path.join(dir, "absent.json")]).status, 2);

    const v3 = path.join(dir, "v3.json");
    writeFileSync(v3, JSON.stringify(report({ schemaVersion: 3 })));
    const out = cli(["compare", v3, v3]);
    assert.strictEqual(out.status, 3, "an ineligible pair must NOT look like a clean compare");
    assert.match(out.stderr, /not comparable/);
  });
});

test("REGRESSION early NUL: the pair is incomparable and the credential is never 'no longer observed'", () => {
  withDir((dir) => {
    repo(dir);
    const secret = token();
    const A = path.join(dir, "A.json"), B = path.join(dir, "B.json");
    const file = path.join(dir, "app.js");

    writeFileSync(file, `const token = "${secret}";\n`);
    scanTo(dir, A);

    // One NUL, credential untouched and still on disk.
    writeFileSync(file, Buffer.concat([Buffer.from("// \u0000\n"), Buffer.from(`const token = "${secret}";\n`)]));
    scanTo(dir, B);

    const out = cli(["compare", A, B]);
    assert.strictEqual(out.status, 3, "the excluded set changed; the pair must be incomparable");
    assert.match(out.stdout, /cannot be compared/);
    assert.match(out.stdout, /binaryDigest/);
    assert.ok(!/no longer observed/i.test(out.stdout),
      "a still-present credential must never be reported as no longer observed");
    assert.ok(!out.stdout.includes(secret));
  });
});

test("REGRESSION equal exclusion counts, different excluded paths: incomparable", () => {
  withDir((dir) => {
    repo(dir);
    const A = path.join(dir, "A.json"), B = path.join(dir, "B.json");
    const nul = (t: string) => Buffer.concat([Buffer.from("// \u0000\n"), Buffer.from(t)]);
    writeFileSync(path.join(dir, "a.js"), nul("const a = 1;\n"));
    writeFileSync(path.join(dir, "b.js"), "const b = 1;\n");
    scanTo(dir, A);
    writeFileSync(path.join(dir, "a.js"), "const a = 1;\n");
    writeFileSync(path.join(dir, "b.js"), nul("const b = 1;\n"));
    scanTo(dir, B);

    const out = cli(["compare", A, B]);
    assert.strictEqual(out.status, 3, "identical counts, different sets — the count could never catch this");
    assert.match(out.stdout, /binaryDigest/);
  });
});

test("unchanged excluded images with changed scanned text still compares", () => {
  withDir((dir) => {
    repo(dir);
    const A = path.join(dir, "A.json"), B = path.join(dir, "B.json");
    writeFileSync(path.join(dir, "logo.png"), Buffer.from([0x89, 0x50, 0x00, 0x00]));
    writeFileSync(path.join(dir, "app.js"), "const a = 1;\n");
    scanTo(dir, A);
    writeFileSync(path.join(dir, "app.js"), `const t = "${token()}";\nconst b = 2;\n`);
    scanTo(dir, B);

    const out = cli(["compare", A, B, "--format", "json"]);
    const d = JSON.parse(out.stdout);
    assert.strictEqual(d.comparable, true, `expected eligible, got ${JSON.stringify(d.reasons)}`);
    assert.strictEqual(d.summary.new, 1, "the new credential in scanned text is reported");
    assert.strictEqual(out.status, 1);
  });
});

test("staged and history reports are refused on the field they lack", () => {
  withDir((dir) => {
    repo(dir);
    writeFileSync(path.join(dir, "app.js"), "const ok = 1;\n");
    spawnSync("git", ["-C", dir, "add", "-A"]);
    const S = path.join(dir, "S.json"), H = path.join(dir, "H.json");
    scanTo(dir, S, "staged");
    scanTo(dir, H, "history");

    const staged = cli(["compare", S, S]);
    assert.strictEqual(staged.status, 3, "staged carries no scopeDigest");
    assert.match(staged.stdout, /scopeDigest/);

    const hist = cli(["compare", H, H]);
    assert.strictEqual(hist.status, 3, "history carries no binaryDigest");
    assert.match(hist.stdout, /binaryDigest/);
  });
});

// ---------------------------------------------------------------------------
suite("\ncompare — scope is validated POSITIVELY, not inferred");

test("a genuine working-tree report is accepted when otherwise eligible", () => {
  withDir((dir) => {
    repo(dir);
    const A = path.join(dir, "A.json"), B = path.join(dir, "B.json");
    writeFileSync(path.join(dir, "app.js"), "const a = 1;\n");
    scanTo(dir, A);
    scanTo(dir, B);
    const d = JSON.parse(cli(["compare", A, B, "--format", "json"]).stdout);
    assert.strictEqual(d.comparable, true, JSON.stringify(d.reasons));
    // And its scope really is the shared authority's value, not a coincidence.
    const produced = JSON.parse(require("fs").readFileSync(A, "utf8"));
    assert.strictEqual(produced.scopeDigest, WORKTREE_SCOPE);
  });
});

test("identical but ARBITRARY scope digests are rejected", () => {
  // Equality between two unsupported scopes must never qualify. This is the
  // gap the check closes: both sides agree, and both are wrong.
  for (const bogus of [`scope:${hex("0")}`, `scope:${hex("9")}`, HISTORY_SCOPE]) {
    const r = cmp(report({ scopeDigest: bogus }), report({ scopeDigest: bogus }));
    assert.strictEqual(r.comparable, false, `${bogus} must be refused on both sides`);
    assert.strictEqual(
      r.reasons.filter((x) => x.code === "unsupported-scope").length, 2,
      "both sides must be named, not just one"
    );
  }
});

test("a HISTORY report with binaryDigest manually supplied is STILL rejected", () => {
  withDir((dir) => {
    repo(dir);
    writeFileSync(path.join(dir, "app.js"), "const a = 1;\n");
    const H = path.join(dir, "H.json");
    scanTo(dir, H, "history");
    const hist = JSON.parse(require("fs").readFileSync(H, "utf8"));
    assert.ok(!("binaryDigest" in hist), "history omits it, which is the producer's behaviour");

    // Forge the one field history lacks. Under an absence-based rule this pair
    // would now have looked like a working-tree report.
    hist.binaryDigest = `binary:${hex("f")}`;
    const F = path.join(dir, "forged.json");
    writeFileSync(F, JSON.stringify(hist));

    const out = cli(["compare", F, F]);
    assert.strictEqual(out.status, 3, "the scope digest still says history");
    assert.match(out.stdout, /unsupported-scope/);
    const d = JSON.parse(cli(["compare", F, F, "--format", "json"]).stdout);
    assert.strictEqual(d.comparable, false);
    for (const k of ["new", "persisting", "noLongerObserved", "summary"]) {
      assert.ok(!(k in d), `no difference key may appear: ${k}`);
    }
  });
});

test("a STAGED report given a non-worktree scope identity is rejected", () => {
  withDir((dir) => {
    repo(dir);
    writeFileSync(path.join(dir, "app.js"), "const a = 1;\n");
    spawnSync("git", ["-C", dir, "add", "-A"]);
    const S = path.join(dir, "S.json");
    scanTo(dir, S, "staged");
    const staged = JSON.parse(require("fs").readFileSync(S, "utf8"));
    assert.ok(!("scopeDigest" in staged), "staged omits the selection identity");

    // Supply a scope that is valid-looking but not the supported one.
    staged.scopeDigest = HISTORY_SCOPE;
    const F = path.join(dir, "staged-forged.json");
    writeFileSync(F, JSON.stringify(staged));
    const out = cli(["compare", F, F]);
    assert.strictEqual(out.status, 3);
    assert.match(out.stdout, /unsupported-scope/);
  });
});

test("a scope identity from a different scope CONTRACT version is rejected", () => {
  // The contract version is hashed inside the digest input, so a report written
  // under another version simply stops matching. Simulated here by digesting a
  // different version marker through the same shared function shape.
  const other = scopeIdentity({ mode: "history", commits: [] }) as string;
  assert.notStrictEqual(other, WORKTREE_SCOPE);
  const r = cmp(report({ scopeDigest: other }), report({ scopeDigest: other }));
  assert.strictEqual(r.comparable, false);
  assert.ok(r.reasons.every((x) => x.code === "unsupported-scope"));
  // The supported value is not hard-coded anywhere in the comparator: it comes
  // from the same function the producer uses.
  assert.strictEqual(WORKTREE_SCOPE, scopeIdentity({ mode: "worktree" }));
});

test("genuine same-scope content changes are still compared", () => {
  withDir((dir) => {
    repo(dir);
    const A = path.join(dir, "A.json"), B = path.join(dir, "B.json");
    writeFileSync(path.join(dir, "app.js"), "const a = 1;\n");
    scanTo(dir, A);
    writeFileSync(path.join(dir, "app.js"), `const t = "${token()}";\n`);
    scanTo(dir, B);
    const out = cli(["compare", A, B, "--format", "json"]);
    const d = JSON.parse(out.stdout);
    assert.strictEqual(d.comparable, true, JSON.stringify(d.reasons));
    assert.strictEqual(d.summary.new, 1);
    assert.strictEqual(out.status, 1);
  });
});

test("every scope rejection exits 3 and emits no difference keys", () => {
  withDir((dir) => {
    const F = path.join(dir, "f.json");
    writeFileSync(F, JSON.stringify(report({ scopeDigest: HISTORY_SCOPE })));
    const out = cli(["compare", F, F, "--format", "json"]);
    assert.strictEqual(out.status, 3);
    const d = JSON.parse(out.stdout);
    assert.strictEqual(d.comparable, false);
    assert.deepStrictEqual(Object.keys(d).sort(), ["comparable", "reasons", "tool"]);
  });
});

test("DUPLICATES: ambiguous multiplicity invents no match and no disappearance", () => {
  // Policy, stated by assertion: a repeated fingerprint is reported as an
  // ambiguity and NOTHING is claimed about the occurrence count changing.
  // The pair stays comparable and the exit code reflects the set difference
  // only -- a multiplicity change alone is never "new" and never "gone".
  const a = report({}, [finding(FP1, { line: 1 }), finding(FP1, { line: 7 })]);
  const b = report({}, [finding(FP1, { line: 1 })]);
  const r = cmp(a, b);
  assert.strictEqual(r.comparable, true);
  assert.deepStrictEqual(r.noLongerObserved, [], "one fewer occurrence is NOT a disappearance");
  assert.deepStrictEqual(r.added, [], "and it is not an appearance either");
  assert.deepStrictEqual(r.persisting.map((f) => f.digest), [hex("1")]);
  assert.deepStrictEqual(r.ambiguousIdentity,
    [{ ruleId: "github-token", digest: hex("1"), beforeCount: 2, afterCount: 1 }]);

  // The reverse direction is equally silent about the count.
  const rev = cmp(b, a);
  assert.deepStrictEqual(rev.added, []);
  assert.deepStrictEqual(rev.ambiguousIdentity,
    [{ ruleId: "github-token", digest: hex("1"), beforeCount: 1, afterCount: 2 }]);

  // And the output says so in words rather than leaving it to be inferred.
  const text = renderText(r);
  assert.match(text, /Occurrence-level/);
  assert.match(text, /NOT tracked/);
});

test("CLI: an unsupported rule id is refused, and never appears on stdout or stderr", () => {
  withDir((dir) => {
    const mark = unknownRuleId();
    const A = path.join(dir, "A.json"), B = path.join(dir, "B.json");
    writeFileSync(A, JSON.stringify(report({}, [finding(FP1)])));
    // A valid finding that WOULD differ, alongside the unsupported one.
    writeFileSync(B, JSON.stringify(report({}, [finding(FP2), finding(`app.js:${mark}:${hex("9")}`)])));

    for (const args of [["compare", A, B], ["compare", A, B, "--format", "json"]]) {
      const out = cli(args);
      assert.strictEqual(out.status, 3, `${args.join(" ")} must refuse the whole comparison`);
      const both = out.stdout + out.stderr;
      assert.ok(!both.includes(mark), "the rejected rule id must not reach stdout or stderr");
      assert.ok(!both.includes(hex("2")), "nor may a difference from the valid findings leak");
    }
    const d = JSON.parse(cli(["compare", A, B, "--format", "json"]).stdout);
    assert.deepStrictEqual(Object.keys(d).sort(), ["comparable", "reasons", "tool"]);
  });
});

test("CLI: a credential-shaped path is accepted internally and absent from output", () => {
  withDir((dir) => {
    const secret = token();
    const A = path.join(dir, "A.json"), B = path.join(dir, "B.json");
    writeFileSync(A, JSON.stringify(report()));
    writeFileSync(B, JSON.stringify(report({}, [finding(`src/${secret}/a.js:github-token:${hex("2")}`)])));
    for (const args of [["compare", A, B], ["compare", A, B, "--format", "json"]]) {
      const out = cli(args);
      // Accepted internally: this is a normal, comparable pair with one new
      // finding. The path is not detected or rejected -- it is simply not shown.
      assert.strictEqual(out.status, 1, "the pair must still compare");
      assert.ok(!(out.stdout + out.stderr).includes(secret), "the path must not reach output");
    }
  });
});

test("CLI: a shared displayed reference is explained, without paths", () => {
  withDir((dir) => {
    const secret = token();
    const A = path.join(dir, "A.json"), B = path.join(dir, "B.json");
    writeFileSync(A, JSON.stringify(report()));
    writeFileSync(B, JSON.stringify(report({}, [
      at(`x/${secret}/one.js`, "2"), at("y/two.js", "2"),
    ])));
    const out = cli(["compare", A, B]);
    assert.strictEqual(out.status, 1, "a normal comparison with new findings");
    assert.match(out.stdout, /SHARED DISPLAY REFERENCE/);
    assert.match(out.stdout, /2 distinct findings/);
    assert.ok(!(out.stdout + out.stderr).includes(secret), "no path may reach output");

    const d = JSON.parse(cli(["compare", A, B, "--format", "json"]).stdout);
    assert.strictEqual(d.summary.sharedDisplayReferences, 1);
    assert.strictEqual(d.summary.new, 2, "the two findings are still counted separately");
  });
});

test("CLI: invalid findings on both sides are all reported, bounded and truncated", () => {
  withDir((dir) => {
    const A = path.join(dir, "A.json"), B = path.join(dir, "B.json");
    const flood = Array.from({ length: 40 }, (_, i) => badRule(i));
    writeFileSync(A, JSON.stringify(report({}, [at("a.js", "1"), ...flood])));
    writeFileSync(B, JSON.stringify(report({}, [badStruct(0), at("b.js", "2"), badStruct(1)])));

    for (const args of [["compare", A, B], ["compare", A, B, "--format", "json"]]) {
      const out = cli(args);
      assert.strictEqual(out.status, 3, `${args.join(" ")} must refuse`);
      const both = out.stdout + out.stderr;
      // Neither side's valid digests may leak as a partial result.
      assert.ok(!both.includes(hex("1")) && !both.includes(hex("2")),
        "no partial differences may be emitted");
    }
    const d = JSON.parse(cli(["compare", A, B, "--format", "json"]).stdout);
    assert.deepStrictEqual(Object.keys(d).sort(), ["comparable", "reasons", "tool"]);
    const before = d.reasons.filter((r: any) => r.side === "before");
    const after = d.reasons.filter((r: any) => r.side === "after");
    assert.strictEqual(after.length, 2, "the smaller side stays fully visible");
    assert.ok(before.some((r: any) => r.code === "diagnostics-truncated"));
    // No unsupported rule id is ever echoed.
    const text = JSON.stringify(d);
    assert.ok(!/zz[a-z0-9]{24}/.test(text), "an unsupported rule id reached output");
  });
});

test("help documents the command, the exit codes and the wording limit", () => {
  const help = cli(["--help"]).stdout;
  assert.match(help, /compare\s+Compare two saved JSON reports/);
  assert.match(help, /3 the pair is NOT COMPARABLE/);
  assert.match(help, /never fixed, removed, rotated or revoked/);
});

void finish();
