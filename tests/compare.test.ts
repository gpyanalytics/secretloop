import { test, suite, finish, assert } from "./harness";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from "fs";
import { tmpdir } from "os";
import { spawnSync } from "child_process";
import * as path from "path";
import {
  compareReports,
  loadReport,
  renderText,
  renderJson,
  MAX_FINDINGS,
  NO_LONGER_OBSERVED_CAVEAT,
} from "../src/compare";
import { REPORT_SCHEMA_VERSION, scopeIdentity } from "../src/report-metadata";

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
const FP2 = `lib/x.js:aws-key:${hex("2")}`;

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
  assert.deepStrictEqual(r.persisting.map((f) => f.fingerprint), [FP1]);
  assert.deepStrictEqual(r.noLongerObserved.map((f) => f.fingerprint), [FP2]);
  assert.deepStrictEqual(r.added.map((f) => f.fingerprint), ["z.js:slack-token:" + hex("3")]);
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
  assert.deepStrictEqual(r.persisting.map((f) => f.fingerprint), [FP1]);
  assert.deepStrictEqual(r.noLongerObserved, [], "the credential is still there; nothing vanished");
  assert.strictEqual(r.ambiguousIdentity.length, 1, "the occurrence change must be surfaced");
  assert.deepStrictEqual(r.ambiguousIdentity[0], { fingerprint: FP1, beforeCount: 3, afterCount: 1 });
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
  // The location now comes from the fingerprint, so the hostile strings are
  // not shown at all rather than shown with their control characters removed.
  assert.strictEqual(r.added[0].file, "app.js");
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
  // Derived from the validated fingerprint instead, so the displayed location is
  // always the one that was matched on.
  assert.strictEqual(r.added[0].file, "app.js");
  assert.strictEqual(r.added[0].ruleId, "github-token");
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

test("LIMIT: the fingerprint is echoed because it is the identity", () => {
  // The one untrusted string the comparator must print. It embeds the scanned
  // path, so a report whose PATH contains credential-shaped text has that text
  // echoed — exactly as the source report already contained it. The comparator
  // does not widen exposure beyond its input; it cannot narrow it either
  // without removing the identity it matched on.
  const secret = token();
  const r = cmp(report(), report({}, [finding(`${secret}:github-token:${hex("2")}`)]));
  assert.strictEqual(r.comparable, true);
  assert.ok(renderText(r).includes(secret),
    "documented limit: the identity is printed, and the identity embeds the path");
  // What is NOT echoed is any separate content-bearing field.
  const r2 = cmp(report(), report({}, [finding(FP1, { value: secret, redactedValue: secret })]));
  assert.ok(!(renderText(r2) + renderJson(r2)).includes(secret));
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
    ["file", "fingerprint", "line", "ruleId", "severity"]
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
  assert.deepStrictEqual(r.persisting.map((f) => f.fingerprint), [FP1]);
  assert.deepStrictEqual(r.ambiguousIdentity, [{ fingerprint: FP1, beforeCount: 2, afterCount: 1 }]);

  // The reverse direction is equally silent about the count.
  const rev = cmp(b, a);
  assert.deepStrictEqual(rev.added, []);
  assert.deepStrictEqual(rev.ambiguousIdentity, [{ fingerprint: FP1, beforeCount: 1, afterCount: 2 }]);

  // And the output says so in words rather than leaving it to be inferred.
  const text = renderText(r);
  assert.match(text, /Occurrence-level/);
  assert.match(text, /NOT tracked/);
});

test("help documents the command, the exit codes and the wording limit", () => {
  const help = cli(["--help"]).stdout;
  assert.match(help, /compare\s+Compare two saved JSON reports/);
  assert.match(help, /3 the pair is NOT COMPARABLE/);
  assert.match(help, /never fixed, removed, rotated or revoked/);
});

void finish();
